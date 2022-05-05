#include "pattern.hpp"
#include "../win/win_helper.hpp"


#define in_range(x,a,b)  (x >= a && x <= b) 
#define get_bits( x )    (in_range((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xA) : (in_range(x,'0','9') ? x - '0' : 0))
#define get_byte( x )    (get_bits(x[0]) << 4 | get_bits(x[1]))


uintptr_t pattern::find
(
    uintptr_t image,
    const char* pat
)
{
    if( image == -1 )
        image = reinterpret_cast< uintptr_t >( win::image_base() );

    uintptr_t start = image;
    uintptr_t end = start + win::img_size( reinterpret_cast< uint8_t* >( image ) );

    return find_ex( start, end, pat );
}



uintptr_t pattern::find_rel32
(
    uintptr_t image,
    const char* pat,
    int32_t offset
)
{
    if( image == -1 )
        image = reinterpret_cast< uintptr_t >( win::image_base() );

    uintptr_t start = image;
    uintptr_t end = start + win::img_size( reinterpret_cast< uint8_t* >( image ) );

    return find_rel32_ex( start, end, pat, offset );
}



uintptr_t pattern::find_string_ref
(
    uintptr_t image,
    const char* str
)
{
    if( image == -1 )
        image = reinterpret_cast< uintptr_t >( win::image_base() );

    uintptr_t start = image;
    uintptr_t end = start + win::img_size( reinterpret_cast< uint8_t* >( image ) );

    return find_string_ref_ex( start, end, str );
}



uintptr_t pattern::find_raw( uintptr_t image, uint8_t* pattern_data, size_t pattern_size )
{
    if( image == -1 )
        image = reinterpret_cast< uintptr_t >( win::image_base() );

    uintptr_t start = image;
    uintptr_t end = start + win::img_size( reinterpret_cast< uint8_t* >( image ) );

    return find_raw_ex( start, end, pattern_data, pattern_size );
}



uintptr_t pattern::find_ex
(
    uintptr_t start,
    uintptr_t end,
    const char* pattern
)
{
    uintptr_t match = 0;
    auto pat = const_cast< char* >( pattern );

    for( uintptr_t cur = start; cur < end; ++cur )
    {
        if( !*pat )
        {
            return match;
        }

        if( *reinterpret_cast< char* >( pat ) == '\?'
            || *reinterpret_cast< char* >( cur ) == get_byte( pat ) )
        {
            if( !match )
            {
                match = cur;
            }
            if( !pat[ 2 ] )
            {
                return match;
            }
            if( *reinterpret_cast< wchar_t* >( pat ) == '\?\?'
                || *reinterpret_cast< char* >( pat ) != '\?' )
            {
                pat += 3;
            }
            else
            {
                pat += 2;
            }
        }
        else
        {
            pat = const_cast< char* >( pattern );
            match = 0;
        }
    }

    return 0;
}



uintptr_t pattern::find_rel32_ex
(
    uintptr_t start,
    uintptr_t end,
    const char* pattern,
    int32_t offset_offset
)
{
    uintptr_t data = find_ex( start, end, pattern );

    if( data == 0 )
    {
        return 0;
    }

    return rel32_to_abs64( data, offset_offset );
}



uintptr_t pattern::find_string_ref_ex
(
    uintptr_t start,
    uintptr_t end,
    const char* str
)
{
    // find_ex the global string pointer
    size_t string_len = strlen( str );

    uintptr_t string_ptr = find_raw_ex( start, end, ( uint8_t* )str, string_len );

    if( string_ptr == 0 )
        return 0;

    // find_ex refs in the code
    uint32_t  pattern_pos = 0;
    uint32_t  bytes_found = 0;
    uintptr_t current = start;

    while( current < end )
    {
        uint8_t rel_32_offset;

        if( is_rel32_opcode_x64( reinterpret_cast< uint8_t* >( current ) , &rel_32_offset ) )
        {
            if( rel32_to_abs64( current, rel_32_offset ) == string_ptr )
            {
                return current;
            }
        }

        current++;
    }

    return 0;
}



uintptr_t pattern::find_raw_ex
(
    uintptr_t start,
    uintptr_t end,
    uint8_t* pattern_data,
    size_t   pattern_size
)
{
    uint32_t  pattern_pos = 0;
    uint32_t  bytes_found = 0;
    uintptr_t current = start;

    while( current < end )
    {
        uint8_t current_byte = *reinterpret_cast< uint8_t* >( current );
        uint8_t pattern_byte = pattern_data[ pattern_pos ];

        if( current_byte == pattern_byte )
        {
            bytes_found++;
            pattern_pos++;

            if( pattern_pos >= pattern_size )
            {
                return current - bytes_found + 1;
            }
        }
        else
        {
            bytes_found = 0;
            pattern_pos = 0;
        }

        current++;
    }

    return 0;
}



bool pattern::is_rel32_opcode_x64
(
    uint8_t* code,
    uint8_t* out_rel32_offset
)
{
    struct opcode_info
    {
        uint8_t opcode;
        uint8_t offset;
    };

    static struct opcode_info opcodes[] =
    {
        { 0x4C, +3 },
        { 0x48, +3 },
        { 0xE8, +1 },
        { 0xE9, +1 }
    };

    for( const auto& opcode : opcodes )
    {
        if( code[ 0 ] == opcode.opcode )
        {
            if( out_rel32_offset )
                *out_rel32_offset = opcode.offset;

            return true;
        }
    }

    return false;
}



uintptr_t pattern::rel32_to_abs64
(
    uintptr_t src,
    int32_t offset_offset
)
{
    if( src == 0 )
        return 0;

    return src + offset_offset + sizeof( int32_t ) + *( int32_t* )( src + offset_offset );
}