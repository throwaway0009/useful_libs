#define _CRT_SECURE_NO_WARNINGS

#include "proc.h"

handle_t proc_open
( 
	handle_t pid, 
	ulong_t flags 
)
{
	handle_t h;
	OBJECT_ATTRIBUTES oa;
	CLIENT_ID cid;

	cid.UniqueProcess = pid;
	cid.UniqueThread = 0;

	InitializeObjectAttributes( &oa, 0, 0, 0, 0 );

	/*
		opens a handle to a process object and sets the
		access rights to this object
	*/
	return ( NT_SUCCESS( NtOpenProcess( &h, flags, &oa, &cid ) ) ? h : NULL );
}

void proc_close
( 
	handle_t h 
)
{
    /* routine closes an object handle */
    NtClose( h );
}

void proc_terminate
( 
	handle_t h 
)
{
    /* routine terminates a process and all of its threads */
    NtTerminateProcess( h, STATUS_SUCCESS );
}

void* proc_vmalloc
( 
	handle_t h, 
	size_t size, 
	ulong_t alloctype, 
	ulong_t flags 
)
{
	void* p = 0;

	/*
		routine reserves, commits, or both, a region of pages within the
		user-mode virtual address space of a specified process
	*/
	return ( NT_SUCCESS( NtAllocateVirtualMemory( h, &p, 0, &size, alloctype,
		flags ) ) ? p : NULL );
}

bool_t proc_vmfree
( 
	handle_t h, 
	void* p 
)
{
	size_t size = 0;

	/*
		routine releases, decommits, or both, a region of pages within the
		virtual address space of a specified process
	*/
	return NT_SUCCESS( NtFreeVirtualMemory( h, &p, &size, MEM_RELEASE ) );
}

ulong_t proc_vmprotect
( 
	handle_t h, 
	void* addr, 
	size_t size, 
	ulong_t flags 
)
{
	/*
		process object opened with PROCESS_VM_OPERATION access
		protection will change on all pages containing specified address
	*/
	return ( NT_SUCCESS( NtProtectVirtualMemory( h, &addr, &size, flags,
		&flags ) ) ? flags : 0 );
}

size_t proc_vmwrite
( 
	handle_t h, 
	void* addr, 
	void* buffer, 
	size_t size 
)
{
	/* written bytes */
	size_t wr = 0;

	/*
		routine writes data to an area of memory in a specified process;
		the entire area to be written to must be accessible or the operation
		fails
	*/
	return ( NT_SUCCESS( NtWriteVirtualMemory( h, addr, buffer, size,
		&wr ) ) ? wr : 0 );
}

#pragma optimize( "", off )
size_t proc_vmread
( 
	handle_t h, 
	void* addr, 
	void* buffer, 
	size_t size 
)
{
	/* read bytes */
	size_t rd = 0;

	/*
		routine reads data from an area of memory in a specified process;
		the entire area to be read must be accessible or the operation fails
	*/
	NTSTATUS status = NtReadVirtualMemory( h, addr, buffer, size, &rd );

	if( NT_SUCCESS( status ) )
	{
		return rd;
	}
	else
	{
		return 0;
	}
}
#pragma optimize( "", on )

void proc_vmreadpages
( 
	handle_t h, 
	void* addr, 
	void* buffer, 
	size_t size 
)
{
    size_t total_bytes = 0;

    /* read pages and ignore failures */
    while( total_bytes < size )
    {
        proc_vmread( h,
            ( uint8_t* )addr + total_bytes,
            ( uint8_t* )buffer + total_bytes,
            0x1000 );

        total_bytes += 0x1000;
    }
}

size_t proc_vmquery
( 
	handle_t h,
	void* addr,
	MEMORY_BASIC_INFORMATION* mbi,
	size_t size 
)
{
	/*
		routine determines the state, protection, and type of a region of
		pages within the virtual address space of the subject process
	*/
	return ( NT_SUCCESS( NtQueryVirtualMemory( h, addr, MemoryBasicInformation,
		mbi, size, &size ) ) ? size : 0 );
}

void proc_get_peb
( 
	handle_t h,
	void** peb,
	void** peb_wow64
)
{
    PROCESS_BASIC_INFORMATION pbi;

    /* null-out struct */
    memset( &pbi, 0, sizeof( pbi ) );

    /* always returns x64 peb */
    NtQueryInformationProcess( h, ProcessBasicInformation, &pbi,
        sizeof( pbi ), NULL );

    if( peb_wow64 )
    {
        /* wow64 peb (32-bit proc running in compatibility mode) */
        NtQueryInformationProcess( h, ProcessWow64Information, peb_wow64,
            sizeof( *peb_wow64 ), NULL );
    }

    if( peb )
    {
        *peb = ( void* )pbi.PebBaseAddress;
    }
}

bool_t thread_suspend
( 
	handle_t h, 
	ulong_t* prev_susp_count 
)
{
    /* routine suspends the specified thread */
    return NT_SUCCESS( NtSuspendThread( h, prev_susp_count ) );
}

bool_t thread_resume
( 
	handle_t h 
)
{
	/*
		routine resumes the specified thread

		difference between AlertResumeThread and ResumeThread is that the
		first one sets the thread object to alerted state (so before thread
		will continue execution, all APC will be executed)
	*/
	return NT_SUCCESS( NtResumeThread( h, NULL ) );
}

bool_t process_get_by_name
( 
	wchar_t* proc_name,
	handle_t* out_pid 
)
{
    NTSTATUS status;
    void* buffer = NULL;
    PSYSTEM_PROCESS_INFO spi = NULL;
    ulong_t buffer_size = 0x2000;

    do
    {
        buffer = proc_vmalloc( NtCurrentProcess(), buffer_size,
            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );

        spi = ( PSYSTEM_PROCESS_INFO )buffer;

        status = NtQuerySystemInformation( SystemProcessInformation,
            spi, buffer_size, &buffer_size );

        if( status == STATUS_INFO_LENGTH_MISMATCH )
        {
            proc_vmfree( NtCurrentProcess(), spi );
            spi = NULL;
        }

    } while( status == STATUS_INFO_LENGTH_MISMATCH );

    if( !spi )
    {
        return false;
    }

    while( spi->NextEntryOffset )
    {
        if( spi->ImageName.Buffer == NULL )
        {
            spi = ( PSYSTEM_PROCESS_INFO )( ( LPBYTE )spi + spi->NextEntryOffset );
            continue;
        }
		
        if( !wcscmp( proc_name, spi->ImageName.Buffer ) )
        {
            *out_pid = spi->ProcessId;
            proc_vmfree( NtCurrentProcess(), buffer );
            return true;
        }

        spi = ( PSYSTEM_PROCESS_INFO )( ( LPBYTE )spi + spi->NextEntryOffset );
    }

    proc_vmfree( NtCurrentProcess(), buffer );

    return false;
}

void* module_get_base
( 
    handle_t proc_handle, 
    char* mod_name,
    size_t* out_size_of_image, 
    ulong_t proc_type 
)
{
    void* dll_base;

    uint8_t* peb = NULL;
    uint8_t* ldr_data = NULL;
    uint8_t* first_entry = NULL;
    uint8_t* curr_entry = NULL;
    uint8_t* mod = NULL;

    size_t ptr_size;
    size_t offset = 0;

    /* buffer for the module name */
    char tmp[ MAX_PATH ];
    void* buff;
    size_t buff_len;

    /* if no module name is specified, return the curr. image base address */
    if( mod_name == NULL && proc_handle == NtCurrentProcess() )
    {
        return NtCurrentPeb()->ImageBaseAddress;
    }

    /* will contain LDR_DATA_TABLE_ENTRY 64/32 */
    uint8_t ldr_data_table[ 128 ];
    uint8_t ldr_data_table_size;

    /* zero out the ldr data table */
    memset( ldr_data_table, 0, sizeof( ldr_data_table ) );

    if( proc_type == 64 )
    {
        /* 64-bit process */
        ptr_size = sizeof( uint64_t );
        offset = offsetof( PEB64, Ldr );
        ldr_data_table_size = sizeof( LDR_DATA_TABLE_ENTRY64 );

        /* get the native peb */
        proc_get_peb( proc_handle, &peb, NULL );
    }
    else if( proc_type == 32 )
    {
        /* 32-bit process */
        ptr_size = sizeof( uint32_t );
        offset = offsetof( PEB32, Ldr );
        ldr_data_table_size = sizeof( LDR_DATA_TABLE_ENTRY32 );

        /* get the wow64 peb */
        proc_get_peb( proc_handle, NULL, &peb );
    }
    else
    {
        return false;
    }

    /* read the PEB_LDR_DATA */
    if( proc_vmread( proc_handle, peb + offset, &ldr_data, ptr_size ) == 0 )
    {
        return false;
    }

    offset = ( proc_type == 64 ?
        offsetof( PEB_LDR_DATA64, InMemoryOrderModuleList ) :
        offsetof( PEB_LDR_DATA32, InMemoryOrderModuleList ) );

    /* read the InMemoryOrderModuleList */
    if( proc_vmread( proc_handle, ldr_data + offset, &first_entry, ptr_size ) == 0 )
    {
        return false;
    }

    /* loop through the linked list */
    curr_entry = first_entry;

    do
    {
        mod = ( proc_type == 64 ?
            ( uint8_t* )CONTAINING_RECORD( curr_entry, LDR_DATA_TABLE_ENTRY64, InMemoryOrderLinks ) :
            ( uint8_t* )CONTAINING_RECORD( curr_entry, LDR_DATA_TABLE_ENTRY32, InMemoryOrderLinks ) );


        /* read the LDR_DATA_TABLE_ENTRY */
        if( proc_vmread( proc_handle, mod, ldr_data_table, ldr_data_table_size ) == 0 )
        {
            return false;
        }

        /* get BaseDllName info */
        buff = ( proc_type == 64 ?
            ( void* )( ( PLDR_DATA_TABLE_ENTRY64 )ldr_data_table )->BaseDllName.Buffer :
            ( void* )( ( PLDR_DATA_TABLE_ENTRY32 )ldr_data_table )->BaseDllName.Buffer );

        buff_len = ( proc_type == 64 ?
            ( size_t )( ( PLDR_DATA_TABLE_ENTRY64 )ldr_data_table )->BaseDllName.MaximumLength :
            ( size_t )( ( PLDR_DATA_TABLE_ENTRY32 )ldr_data_table )->BaseDllName.MaximumLength );

        /* get dll base */
        dll_base = ( proc_type == 64 ?
            ( void* )( ( PLDR_DATA_TABLE_ENTRY64 )ldr_data_table )->DllBase :
            ( void* )( ( PLDR_DATA_TABLE_ENTRY32 )ldr_data_table )->DllBase );

        /* only check modules with a name and valid base */
        if( buff != NULL && dll_base != NULL )
        {
            bool_t match = false;
            wchar_t base_dll_name[ MAX_PATH ];
            proc_vmread( proc_handle, buff, base_dll_name, buff_len );

            size_t name_len = wcslen( base_dll_name );

            wcstombs( tmp, base_dll_name, name_len );
            match = !strcmp( tmp, mod_name );

            if( proc_type == 64 )
            {
                PLDR_DATA_TABLE_ENTRY64 p =
                    ( PLDR_DATA_TABLE_ENTRY64 )ldr_data_table;

                if( match )
                {
                    if( out_size_of_image )
                    {
                        *out_size_of_image = p->SizeOfImage;
                    }

                    return ( void* )p->DllBase;
                }

                offset = offsetof( LIST_ENTRY64, Flink );
            }
            else
            {
                PLDR_DATA_TABLE_ENTRY32 p =
                    ( PLDR_DATA_TABLE_ENTRY32 )ldr_data_table;

                if( match )
                {
                    if( out_size_of_image )
                    {
                        *out_size_of_image = p->SizeOfImage;
                    }

                    return ( void* )p->DllBase;
                }

                offset = offsetof( LIST_ENTRY32, Flink );
            }
        }

        /* get the next entry */
        if( proc_vmread( proc_handle,
            curr_entry + offset, &curr_entry, ptr_size ) == 0 )
        {
            return false;
        }

    } while( curr_entry != first_entry );

    return NULL;
}

void* remote_get_module
( 
    handle_t proc_handle, 
    char* mod_name,
    void** remote_module_base, 
    ulong_t proc_type 
)
{
    void* result;
    size_t size_of_image;
    void* dll_base;

    /* get the module's info */
    if( ( dll_base = module_get_base( proc_handle,
        mod_name, &size_of_image, proc_type ) ) == NULL )
    {
        return NULL;
    }

    /* allocate enough space locally */
    result = proc_vmalloc( NtCurrentProcess(), size_of_image,
        MEM_COMMIT, PAGE_READWRITE );

    if( result == NULL )
    {
        return NULL;
    }

    /* read the module */
    proc_vmreadpages( proc_handle, dll_base, result, size_of_image );

    if( remote_module_base )
    {
        *remote_module_base = dll_base;
    }

    return result;
}

#if 0

void*
remote_get_proc_address( handle_t proc_handle,
    char* mod_name, char* func_name, ulong_t ord, ulong_t code_type )
{
    PIMAGE_EXPORT_DIRECTORY exp_dir;

    void* remote_mod_base;

    ushort_t* ord_table;
    ulong_t* func_table;
    ulong_t* name_table;

    ulong_t exp_size;
    ulong_t exp_offs;

    void* result = NULL;

    /* get the module info */
    void* mod_base = remote_get_module( proc_handle,
        mod_name, &remote_mod_base, code_type );

    if( mod_base == NULL )
    {
        return NULL;
    }

    /* get the export directory */
    if( pe_get_magic( mod_base ) == IMAGE_NT_OPTIONAL_HDR64_MAGIC )
    {
        /* IMAGE_DIRECTORY_ENTRY_EXPORT = 0 */
        exp_offs = pe64_get_optional_header( mod_base )->DataDirectory[ 0 ].VirtualAddress;
        exp_size = pe64_get_optional_header( mod_base )->DataDirectory[ 0 ].Size;
    }
    else
    {
        /* IMAGE_DIRECTORY_ENTRY_EXPORT = 0 */
        exp_offs = pe32_get_optional_header( mod_base )->DataDirectory[ 0 ].VirtualAddress;
        exp_size = pe32_get_optional_header( mod_base )->DataDirectory[ 0 ].Size;
    }

    exp_dir = ( PIMAGE_EXPORT_DIRECTORY )( ( uint8_t* )mod_base + exp_offs );

    /* get the tables pointers */
    ord_table = ( ushort_t* )( ( uint8_t* )mod_base + exp_dir->AddressOfNameOrdinals );
    func_table = ( ulong_t* )( ( uint8_t* )mod_base + exp_dir->AddressOfFunctions );
    name_table = ( ulong_t* )( ( uint8_t* )mod_base + exp_dir->AddressOfNames );

    if( func_name == NULL )
    {
        /* import by ordinal */
        ulong_t ord_base = exp_dir->Base;

        if( ord < ord_base ||
            ord > ord_base + exp_dir->NumberOfFunctions )
        {
            return NULL;
        }

        result = ( void* )( ( uint8_t* )mod_base + func_table[ ord - ord_base ] );
    }
    else
    {
        /* import by name */
        for( ulong_t i = 0; i < exp_dir->NumberOfNames; i++ )
        {
            char* tmp = ( char* )( ( uint8_t* )mod_base + name_table[ i ] );

            if( !stricmp( tmp, func_name ) )
            {
                result = ( void* )( ( uint8_t* )mod_base + func_table[ ord_table[ i ] ] );
                break;
            }
        }
    }

    /* check if the function is forwarded */
    if( ( uint8_t* )result >= ( uint8_t* )exp_dir &&
        ( uint8_t* )result < ( uint8_t* )exp_dir + exp_size )
    {
        char tmp_func_name[ MAX_PATH ];
        char tmp_mod_name[ MAX_PATH ];

        char* p = strchr( ( char* )result, '.' );

        /* copy the string */
        strncpy( ( char* )tmp_mod_name, ( char* )result, p - ( char* )result );
        strcat( ( char* )tmp_mod_name, ".dll" );
        strcpy( ( char* )tmp_func_name, p + 1 );

        /* recursive call */
        result = remote_get_proc_address( proc_handle, tmp_mod_name,
            ( char* )tmp_func_name, ord, code_type );
    }
    else
    {
        /* output */
        result = ( void* )( ( uint8_t* )result - ( uint8_t* )mod_base +
            ( uint8_t* )remote_mod_base );
    }

    /* free the memory */
    proc_vmfree( NtCurrentProcess(), mod_base );

    return result;
}

#endif