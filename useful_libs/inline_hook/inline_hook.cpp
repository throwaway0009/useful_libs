#include "inline_hook.hpp"

#include <Windows.h>

#if defined(_M_X64)
#include "hde\hde64.h"
#define HDE_DISASM hde64_disasm
#define HDES hde64s
#define JMP_PATCH_SIZE 0x0E
#elif defined(_M_IX86)
#include "hde\hde32.h"
#define HDE_DISASM hde32_disasm
#define HDES hde32s
#define JMP_PATCH_SIZE 0x05
#else
#error Unsupported platform.
#endif

inline_hook::inline_hook( void* addr, void* callback, bool active )
{
    auto address_bytes = reinterpret_cast< uint8_t* >( addr );

    HDES hs;
    _tramp_size = 0;

    do
    {
        _tramp_size += HDE_DISASM( address_bytes + _tramp_size, &hs );
    } while( _tramp_size < JMP_PATCH_SIZE );

    unprotect_memory( addr, _tramp_size );

    _orig_func = new uint8_t[ _tramp_size + JMP_PATCH_SIZE ];
    _orig_func_jmpbk = address_bytes + _tramp_size;
    auto orig_func_addr = reinterpret_cast< uint8_t* >( _orig_func );

    memcpy( _orig_func, addr, _tramp_size );

    unprotect_memory( _orig_func, _tramp_size + JMP_PATCH_SIZE );

    _patched_func = addr;
    _callback_func = callback;

    apply_patch_jmp( orig_func_addr + _tramp_size, _orig_func_jmpbk );

    if( active )
        activate();
    else
        deactivate();
}

void* inline_hook::activate()
{
    apply_patch_jmp( _patched_func, _callback_func );
    _active = true;
    return _orig_func;
}

void inline_hook::deactivate()
{
    apply_patch_jmp( _patched_func, _orig_func );
    _active = false;
}

void inline_hook::uninstall()
{
    memcpy( _patched_func, _orig_func, _tramp_size );

    delete[] _orig_func;
    _active = false;

    delete this;
}

void inline_hook::apply_patch_jmp( void* addr, void* dst )
{
    uint8_t* p_addr = reinterpret_cast< uint8_t* >( addr );

#if defined(_M_IX86)

    /* `JMP dst` */
    p_addr[ 0x00 ] = 0xE9;

    /* set the operand to the relative position to jump to,
       since `JMP <immediate>` is relative */
    *reinterpret_cast< uint32_t* >( &p_addr[ 0x01 ] ) =
        ( reinterpret_cast< uint32_t >( dst ) - reinterpret_cast< uint32_t >( addr ) - JMP_PATCH_SIZE );

#elif defined(_M_X64)

    /* `jmp [RIP]` */
    p_addr[ 0x00 ] = 0xFF;
    p_addr[ 0x01 ] = 0x25;
    p_addr[ 0x02 ] = p_addr[ 0x03 ] = p_addr[ 0x04 ] = p_addr[ 0x05 ] = 0x00;

    /* set the address to jump to; `JMP [RIP]` reads this
       because RIP is at the end of the previous instruction */

    *reinterpret_cast< void** >( &p_addr[ 0x06 ] ) = dst;

#endif
}

int inline_hook::unprotect_memory( void* addr, size_t len, uint32_t* old_protect )
{
    uint32_t tmp_protect = 0;

    int result = VirtualProtect(
        addr,
        len,
        PAGE_EXECUTE_READWRITE,
        reinterpret_cast< PDWORD >( &old_protect )
    );

    if( old_protect )
        *old_protect = tmp_protect;

    return result;
}