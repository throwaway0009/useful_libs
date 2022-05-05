#pragma once
#include <string>
#include <stdint.h>

#include "proc.h"

class process
{
public:
    process( const std::wstring& proc_name, long_t flags = PROCESS_ALL_ACCESS );
    ~process();

    void* alloc( size_t size, ulong_t type, ulong_t flags );
    bool free( void* addr );
    ulong_t protect( void* addr, size_t size, ulong_t flags );

    size_t write_memory( void* addr, void* buffer, size_t size );
    size_t read_memory( void* addr, void* buffer, size_t size );

    void* get_module( const std::string& name, size_t* size_of_image, ulong_t proc_type );
    void* get_proc_address( const std::string& mod_name, const std::string& func_name, ulong_t ord, ulong_t code_type );

    template<typename T, typename U>
    T read( U address )
    {
        T temp;
        read_memory( ( void* )address, &temp, sizeof( T ) );
        return temp;
    }

    template<typename T, typename U>
    bool write( U address, T value )
    {
        return write_memory( ( void* )address, &value, sizeof( T ) );
    }

private:
    handle_t find_process_by_name( const std::wstring& proc_name );

private:
    handle_t _handle;
    handle_t _pid;
};