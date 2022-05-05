#ifndef WinSystemInfoQuery_h__
#define WinSystemInfoQuery_h__
/*******************************************************************************
	BattlBye
	WinSystemInfoQuery.hpp
*******************************************************************************/
#include "proc.h"
#include <vector>
#include <string>

template <class T>
class WinSystemInfoQuery
{
private:
	bool _initialised;
	std::vector<uint8_t> _buffer;
	SYSTEM_INFORMATION_CLASS _si;

public:
	WinSystemInfoQuery( SYSTEM_INFORMATION_CLASS sys_info_class ) :
		_initialised( false ), _si( sys_info_class )
	{ }

	NTSTATUS exec()
	{
		NTSTATUS status;
		ULONG return_size;

		ulong_t buffer_size = ( ulong_t )max( _buffer.size(), 0x1000 );

		do
		{
			_buffer.reserve( buffer_size );

			status = NtQuerySystemInformation( _si,
				_buffer.data(), buffer_size, &return_size );

			if( status == STATUS_INFO_LENGTH_MISMATCH )
			{
				buffer_size = return_size;
			}

		} while( status == STATUS_INFO_LENGTH_MISMATCH );

		_initialised = NT_SUCCESS( status );

		return status;
	}

	T* get()
	{
		return _initialised ? ( T* )_buffer.data() : nullptr;
	}
};

class SystemModuleInformationQuery :
	public WinSystemInfoQuery<RTL_PROCESS_MODULES>
{
public:
	SystemModuleInformationQuery() :
		WinSystemInfoQuery<RTL_PROCESS_MODULES>
		( SystemModuleInformation )
	{ }

	bool find_module(
		const std::string& name,
		RTL_PROCESS_MODULE_INFORMATION& info_out )
	{
		auto buffer = get();

		for( uint32_t i = 0; i < buffer->NumberOfModules; i++ )
		{
			RTL_PROCESS_MODULE_INFORMATION* info = &buffer->Modules[ i ];
			UCHAR* file_name = info->FullPathName + info->OffsetToFileName;

			if( name == ( char* )file_name )
			{
				info_out = *info;
				return true;
			}
		}

		return false;
	}
};

class SystemProcessInformationExQuery :
	public WinSystemInfoQuery<SYSTEM_PROCESS_INFORMATION>
{
public:
	SystemProcessInformationExQuery() :
		WinSystemInfoQuery<SYSTEM_PROCESS_INFORMATION>
		( SystemProcessInformation )
	{ }

	handle_t get_proc_id( const std::wstring& name )
	{
		auto buffer = get();

		while( buffer->NextEntryOffset )
		{
			if( buffer->ImageName.Buffer == NULL )
			{
				buffer = ( PSYSTEM_PROCESS_INFORMATION )(
					( BYTE* )buffer + buffer->NextEntryOffset );

				continue;
			}

			if( name == buffer->ImageName.Buffer )
			{
				return buffer->UniqueProcessId;
			}

			buffer = ( PSYSTEM_PROCESS_INFORMATION )(
				( BYTE* )buffer + buffer->NextEntryOffset );
		}

		return nullptr;
	}
};

class SystemHandleInformationExQuery :
	public WinSystemInfoQuery<SYSTEM_HANDLE_INFORMATION_EX>
{
public:
	SystemHandleInformationExQuery() :
		WinSystemInfoQuery<SYSTEM_HANDLE_INFORMATION_EX>
		( SystemExtendedHandleInformation )
	{ }
};

class SystemThreadInformationExQuery :
	public WinSystemInfoQuery <SYSTEM_PROCESS_INFORMATION>
{
public:
	SystemThreadInformationExQuery() :
		WinSystemInfoQuery <SYSTEM_PROCESS_INFORMATION>
		( SystemExtendedProcessInformation )
	{ }
};

#endif // WinSystemInfoQuery_h__
