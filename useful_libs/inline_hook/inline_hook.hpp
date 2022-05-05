#pragma once
#include <stdint.h>

class inline_hook
{
private:
    inline_hook( void* addr, void* callback, bool active );

public:

    static inline inline_hook& install( void* addr, void* callback, bool active = false )
    {
        return *new inline_hook( addr, callback, active );
    }

    void* activate();
    void deactivate();
    void uninstall();

    inline bool active() { return _active; }
    inline void* orig_func_jmpbk() { return _orig_func_jmpbk; }
    inline void* patched_func() { return _patched_func; }
    inline void* callback_func() { return _callback_func; }
    inline void* orig_func() { return _orig_func; }
    inline size_t tramp_size() { return _tramp_size; }

private:
    void apply_patch_jmp( void* addr, void* dst );
    int unprotect_memory( void* addr, size_t len, uint32_t* old_protect = nullptr );

private:

    bool _active;

    void* _orig_func;
    void* _orig_func_jmpbk;
    void* _patched_func;
    void* _callback_func;

    size_t _tramp_size;
};