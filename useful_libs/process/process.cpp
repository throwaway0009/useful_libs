#include "process.hpp"
#include <stdexcept>
#include "WinSysteminfoQuery.hpp"

process::process( const std::wstring& proc_name, long_t flags )
{
    auto pid = find_process_by_name( proc_name );

    if( !pid )
        throw std::runtime_error( "Failed to find process." );

    handle_t handle = proc_open( pid, flags );

    if( !handle )
        throw std::runtime_error( "Failed to open handle to process." );

    _handle = handle;
}

process::~process()
{
    if( _handle )
        proc_close( _handle );

    _pid = 0;
    _handle = 0;
}

void* process::alloc
( 
    size_t size, 
    ulong_t type, 
    ulong_t flags 
)
{
    if( !_handle ) return nullptr;
    return proc_vmalloc( _handle, size, type, flags );
}

bool process::free
( 
    void* addr 
)
{
    if( !_handle ) return false;
    return proc_vmfree( _handle, addr );
}

ulong_t process::protect
(
    void* addr,
    size_t size,
    ulong_t flags
)
{
    if( !_handle ) return 0;
    return proc_vmprotect( _handle, addr, size, flags );
}

size_t process::write_memory
( 
    void* addr, 
    void* buffer, 
    size_t size 
)
{
    if( !_handle ) return 0;
    return proc_vmwrite( _handle, addr, buffer, size );
}

size_t process::read_memory
( 
    void* addr, 
    void* buffer,
    size_t size 
)
{
    if( !_handle ) return 0;

    return proc_vmread( _handle, addr, buffer, size );
}

void* process::get_module
( 
    const std::string& name, 
    size_t* size_of_image,
    ulong_t proc_type 
)
{
    return module_get_base( _handle, (char*)name.c_str(), size_of_image, proc_type );
}

void* process::get_proc_address
( 
    const std::string& mod_name,
    const std::string& func_name,
    ulong_t ord, ulong_t code_type
)
{
    // return remote_get_proc_address(_handle, mod_name, func_name, ord, code_type);
    return nullptr;
}

handle_t process::find_process_by_name
( 
    const std::wstring& proc_name 
)
{
    NTSTATUS status;
    SystemProcessInformationExQuery query;

    if( !NT_SUCCESS( status = query.exec() ) )
    {
        throw std::runtime_error( "Failed to query SystemProcessInformation." );
        return nullptr;
    }

    return query.get_proc_id( proc_name );
}