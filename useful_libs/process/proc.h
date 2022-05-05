#pragma warning( disable : 4312 )

#ifndef _PROC_H_
#define _PROC_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "types.h"
#include "..\ntdll\ntdll.h"

    /* opens a process given its id */
    handle_t proc_open( handle_t pid, ulong_t flags );

    /* closes a process handle */
    void proc_close( handle_t h );

    /* allocates virtual memory page */
    void* proc_vmalloc( handle_t h, size_t size, ulong_t alloctype, ulong_t flags );

    /* frees virtual memory page */
    bool_t proc_vmfree( handle_t h, void* address );

    /* sets the protection of a specified memory page(s) */
    ulong_t proc_vmprotect( handle_t h, void* address, size_t size, ulong_t flags );

    /* writes the content of buffer to address */
    size_t proc_vmwrite( handle_t h, void* address, void* buffer, size_t size );

    /* reads the content at address into buffer */
    size_t proc_vmread( handle_t h, void* address, void* buffer, size_t size );

    /* get the PEB address(es) of the specified process */
    void proc_get_peb( handle_t h, void** peb, void** peb_wow64 );

    /* get process id by name */
    bool_t process_get_by_name( wchar_t* name, handle_t* out_pid );

    /* suspend a thread by handle */
    bool_t thread_suspend( handle_t h, ulong_t* prev_susp_count );

    /* resume a thread by handle */
    bool_t thread_resume( handle_t h );

    /* get a module base address */
    void* module_get_base( handle_t proc_handle, char* mod_name,
        size_t* out_size_of_image, ulong_t proc_type );

    void* remote_get_proc_address( handle_t proc_handle, char* mod_name,
        char* func_name, ulong_t ord, ulong_t proc_type );

    void image_base_size( uint64_t* out_image_base, uint32_t* out_image_size );

    /****************************************************************************

        structures and defines -- misc structures

    ****************************************************************************/
    typedef struct _SYSTEM_OBJECTTYPE_INFORMATION
    {
        ULONG NextEntryOffset;
        ULONG NumberOfObjects;
        ULONG NumberOfHandles;
        ULONG TypeIndex;
        ULONG InvalidAttributes;
        GENERIC_MAPPING GenericMapping;
        ULONG ValidAccessMask;
        ULONG PoolType;
        BOOLEAN SecurityRequired;
        BOOLEAN WaitableObject;
        UNICODE_STRING TypeName;
    } SYSTEM_OBJECTTYPE_INFORMATION, * PSYSTEM_OBJECTTYPE_INFORMATION;

    typedef struct _SYSTEM_OBJECT_INFORMATION
    {
        ULONG NextEntryOffset;
        PVOID Object;
        HANDLE CreatorUniqueProcess;
        USHORT CreatorBackTraceIndex;
        USHORT Flags;
        LONG PointerCount;
        LONG HandleCount;
        ULONG PagedPoolCharge;
        ULONG NonPagedPoolCharge;
        HANDLE ExclusiveProcessId;
        PVOID SecurityDescriptor;
        UNICODE_STRING NameInfo;
    } SYSTEM_OBJECT_INFORMATION, * PSYSTEM_OBJECT_INFORMATION;

    typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
        USHORT UniqueProcessId;
        USHORT CreatorBackTraceIndex;
        UCHAR ObjectTypeIndex;
        UCHAR HandleAttributes;
        USHORT HandleValue;
        PVOID Object;
        ULONG GrantedAccess;
    } SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

    typedef struct _SYSTEM_HANDLE_INFORMATION {
        ULONG NumberOfHandles;
        SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[ 1 ];
    } SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

    typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
        PVOID Object;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR HandleValue;
        ULONG GrantedAccess;
        USHORT CreatorBackTraceIndex;
        USHORT ObjectTypeIndex;
        ULONG  HandleAttributes;
        ULONG  Reserved;
    } SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

    typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
        ULONG_PTR NumberOfHandles;
        ULONG_PTR Reserved;
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[ 1 ];
    } SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

    typedef struct __PUBLIC_OBJECT_TYPE_INFORMATION {
        UNICODE_STRING TypeName;
        ULONG          Reserved[ 22 ];
    } PUBLIC_OBJECT_TYPE_INFORMATION, * PPUBLIC_OBJECT_TYPE_INFORMATION;

    typedef struct _SYSTEM_SESSION_PROCESS_INFORMATION {
        ULONG SessionId;
        ULONG SizeOfBuf;
        PVOID Buffer;
    } SYSTEM_SESSION_PROCESS_INFORMATION, * PSYSTEM_SESSION_PROCESS_INFORMATION;

    typedef struct _SYSTEM_EXTENDED_THREAD_INFORMATION {
        SYSTEM_THREAD_INFORMATION ThreadInfo;
        PVOID StackBase;
        PVOID StackLimit;
        PVOID Win32StartAddress;
        ULONG_PTR Reserved1;
        ULONG_PTR Reserved2;
        ULONG_PTR Reserved3;
        ULONG_PTR Reserved4;
    } SYSTEM_EXTENDED_THREAD_INFORMATION, * PSYSTEM_EXTENDED_THREAD_INFORMATION;

    typedef struct _SYSTEM_MEMORY_INFO {
        PUCHAR StringOffset;
        USHORT ValidCount;
        USHORT TransitionCount;
        USHORT ModifiedCount;
        USHORT PageTableCount;
    } SYSTEM_MEMORY_INFO, * PSYSTEM_MEMORY_INFO;

    typedef struct _SYSTEM_MEMORY_INFORMATION {
        ULONG InfoSize;
        ULONG_PTR StringStart;
        SYSTEM_MEMORY_INFO Memory[ 1 ];
    } SYSTEM_MEMORY_INFORMATION, * PSYSTEM_MEMORY_INFORMATION;

    typedef struct _SYSTEM_PAGEFILE_INFORMATION
    {
        ULONG NextEntryOffset;
        ULONG TotalSize;
        ULONG TotalInUse;
        ULONG PeakUsage;
        UNICODE_STRING PageFileName;
    } SYSTEM_PAGEFILE_INFORMATION, * PSYSTEM_PAGEFILE_INFORMATION;

    /****************************************************************************

        structures and defines -- Process Environment Block (PEB)

    ****************************************************************************/
    // begin_rev
#define PS_ATTRIBUTE_NUMBER_MASK 0x0000ffff
#define PS_ATTRIBUTE_THREAD 0x00010000 // can be used with threads
#define PS_ATTRIBUTE_INPUT 0x00020000 // input only
#define PS_ATTRIBUTE_UNKNOWN 0x00040000
// end_rev

// private
    typedef enum _PS_ATTRIBUTE_NUM
    {
        PsAttributeParentProcess, // in HANDLE
        PsAttributeDebugPort, // in HANDLE
        PsAttributeToken, // in HANDLE
        PsAttributeClientId, // out PCLIENT_ID
        PsAttributeTebAddress, // out PTEB *
        PsAttributeImageName, // in PWSTR
        PsAttributeImageInfo, // out PSECTION_IMAGE_INFORMATION
        PsAttributeMemoryReserve, // in PPS_MEMORY_RESERVE
        PsAttributePriorityClass, // in UCHAR
        PsAttributeErrorMode, // in ULONG
        PsAttributeStdHandleInfo, // 10, in PPS_STD_HANDLE_INFO
        PsAttributeHandleList, // in PHANDLE
        PsAttributeGroupAffinity, // in PGROUP_AFFINITY
        PsAttributePreferredNode, // in PUSHORT
        PsAttributeIdealProcessor, // in PPROCESSOR_NUMBER
        PsAttributeUmsThread, // ? in PUMS_CREATE_THREAD_ATTRIBUTES
        PsAttributeMitigationOptions, // in UCHAR
        PsAttributeMax
    } PS_ATTRIBUTE_NUM;

    // begin_rev

#define PsAttributeValue(Number, Thread, Input, Unknown) \
    (((Number) & PS_ATTRIBUTE_NUMBER_MASK) | \
    ((Thread) ? PS_ATTRIBUTE_THREAD : 0) | \
    ((Input) ? PS_ATTRIBUTE_INPUT : 0) | \
    ((Unknown) ? PS_ATTRIBUTE_UNKNOWN : 0))

#define PS_ATTRIBUTE_PARENT_PROCESS \
    PsAttributeValue(PsAttributeParentProcess, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_DEBUG_PORT \
    PsAttributeValue(PsAttributeDebugPort, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_TOKEN \
    PsAttributeValue(PsAttributeToken, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_CLIENT_ID \
    PsAttributeValue(PsAttributeClientId, TRUE, FALSE, FALSE)
#define PS_ATTRIBUTE_TEB_ADDRESS \
    PsAttributeValue(PsAttributeTebAddress, TRUE, FALSE, FALSE)
#define PS_ATTRIBUTE_IMAGE_NAME \
    PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_IMAGE_INFO \
    PsAttributeValue(PsAttributeImageInfo, FALSE, FALSE, FALSE)
#define PS_ATTRIBUTE_MEMORY_RESERVE \
    PsAttributeValue(PsAttributeMemoryReserve, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_PRIORITY_CLASS \
    PsAttributeValue(PsAttributePriorityClass, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_ERROR_MODE \
    PsAttributeValue(PsAttributeErrorMode, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_STD_HANDLE_INFO \
    PsAttributeValue(PsAttributeStdHandleInfo, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_HANDLE_LIST \
    PsAttributeValue(PsAttributeHandleList, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_GROUP_AFFINITY \
    PsAttributeValue(PsAttributeGroupAffinity, TRUE, TRUE, FALSE)
#define PS_ATTRIBUTE_PREFERRED_NODE \
    PsAttributeValue(PsAttributePreferredNode, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_IDEAL_PROCESSOR \
    PsAttributeValue(PsAttributeIdealProcessor, TRUE, TRUE, FALSE)
#define PS_ATTRIBUTE_MITIGATION_OPTIONS \
    PsAttributeValue(PsAttributeMitigationOptions, FALSE, TRUE, TRUE)

    typedef struct _PS_ATTRIBUTE
    {
        ULONG Attribute;
        SIZE_T Size;
        union
        {
            ULONG Value;
            PVOID ValuePtr;
        };
        PSIZE_T ReturnLength;
    } PS_ATTRIBUTE, * PPS_ATTRIBUTE;

    typedef struct _PS_ATTRIBUTE_LIST
    {
        SIZE_T TotalLength;
        PS_ATTRIBUTE Attributes[ 1 ];
    } PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH 0x00000002 // ?
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004
#define THREAD_CREATE_FLAGS_HAS_SECURITY_DESCRIPTOR 0x00000010 // ?
#define THREAD_CREATE_FLAGS_ACCESS_CHECK_IN_TARGET 0x00000020 // ?
#define THREAD_CREATE_FLAGS_INITIAL_THREAD 0x00000080

    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtCreateThreadEx(
            __out PHANDLE ThreadHandle,
            __in ACCESS_MASK DesiredAccess,
            __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
            __in HANDLE ProcessHandle,
            __in PVOID StartRoutine,
            __in_opt PVOID Argument,
            __in ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
            __in_opt ULONG_PTR ZeroBits,
            __in_opt SIZE_T StackSize,
            __in_opt SIZE_T MaximumStackSize,
            __in_opt PPS_ATTRIBUTE_LIST AttributeList
        );


#define EFLAGS_IF_MASK		0x200
#define RPL_MASK			0x03 

#define PTR_32 uint32_t
#define PTR_64 uint64_t

#pragma pack(push, 4)

    typedef struct _PEB32
    {
        union
        {
            struct
            {
                uint8_t InheritedAddressSpace;
                uint8_t ReadImageFileExecOptions;
                uint8_t BeingDebugged;
            };

            PTR_32/* PVOID */ Data00;
        };

        PTR_32/* HANLDE */ Mutant;
        PTR_32/* PVOID */ ImageBaseAddress;
        PTR_32/* PPEB_LDR_DATA */ Ldr;
        PTR_32/* PRTL_USER_PROCESS_PARAMETERS */ ProcessParameters;
        PTR_32/* PVOID */ SubSystemData;
        PTR_32/* PVOID */ ProcessHeap;
        PTR_32/* PRTL_CRITICAL_SECTION */ FastPebLock;
        PTR_32/* PVOID */ _SYSTEM_DEPENDENT_02;
        PTR_32/* PVOID */ _SYSTEM_DEPENDENT_03;
        PTR_32/* PVOID */ _SYSTEM_DEPENDENT_04;

        union
        {
            PTR_32/* PVOID */ KernelCallbackTable;
            PTR_32/* PVOID */ UserSharedInfoPtr;
        };

        ulong_t SystemReserved;
        ulong_t SpareUlong;

        PTR_32/* PPEB_FREE_BLOCK */ FreeList;
        PTR_32/* ULONG */ TlsExpansionCounter;
        PTR_32/* PVOID */ TlsBitmap;

        ulong_t TlsBitmapBits[ 2 ];

        PTR_32/* PVOID */ ReadOnlySharedMemoryBase;
        PTR_32/* PVOID */ ReadOnlySharedMemoryHeap;
        PTR_32/* PVOID */ ReadOnlyStaticServerData;
        PTR_32/* PVOID */ AnsiCodePageData;
        PTR_32/* PVOID */ OemCodePageData;
        PTR_32/* PVOID */ UnicodeCaseTableData;

        ulong_t NumberOfProcessors;
        ulong_t NtGlobalFlag;

        LARGE_INTEGER CriticalSectionTimeout;

        PTR_32/* SIZE_T */ HeapSegmentReserve;
        PTR_32/* SIZE_T */ HeapSegmentCommit;
        PTR_32/* SIZE_T */ HeapDeCommitTotalFreeThreshold;
        PTR_32/* SIZE_T */ HeapDeCommitFreeBlockThreshold;

        ulong_t NumberOfHeaps;
        ulong_t MaximumNumberOfHeaps;

        PTR_32/* PPVOID */ ProcessHeaps;
        PTR_32/* PVOID */ GdiSharedHandleTable;
        PTR_32/* PVOID */ ProcessStarterHelper;
        PTR_32/* PVOID */ GdiDCAttributeList;
        PTR_32/* PRTL_CRITICAL_SECTION */ LoaderLock;

        ulong_t OSMajorVersion;
        ulong_t OSMinorVersion;
        ushort_t OSBuildNumber;
        ushort_t OSCSDVersion;
        ulong_t OSPlatformId;
        ulong_t ImageSubsystem;
        ulong_t ImageSubsystemMajorVersion;
        ulong_t ImageSubsystemMinorVersion;

    } PEB32, * PPEB32;

#pragma pack(pop)
#pragma pack(push, 8)

    typedef NTSTATUS( NTAPI* KernelCallbackProc ) ( PVOID );

    typedef struct
    {
        KernelCallbackProc fnCOPYDATA;					// 0  +0x0
        KernelCallbackProc fnCOPYGLOBALDATA;            // 1  +0x8
        KernelCallbackProc fnDWORD;                     // 2  +0x10
        KernelCallbackProc fnNCDESTROY;                 // 3  +0x18
        KernelCallbackProc fnDWORDOPTINLPMSG;           // 4  +0x20
        KernelCallbackProc fnINOUTDRAG;                 // 5  +0x28
        KernelCallbackProc fnGETTEXTLENGTHS_6;          // 6  +0x30
        KernelCallbackProc fnINCNTOUTSTRING;            // 7  +0x38
        KernelCallbackProc fnINCNTOUTSTRINGNULL;        // 8  +0x40
        KernelCallbackProc fnINLPCOMPAREITEMSTRUCT;     // 9  +0x48
        KernelCallbackProc fnINLPCREATESTRUCT;          // 10  +0x50
        KernelCallbackProc fnINLPDELETEITEMSTRUCT;      // 11  +0x58
        KernelCallbackProc fnINLPDRAWITEMSTRUCT;        // 12  +0x60
        KernelCallbackProc fnINPGESTURENOTIFYSTRUCT_13; // 13  +0x68
        KernelCallbackProc fnINPGESTURENOTIFYSTRUCT_14; // 14  +0x70
        KernelCallbackProc fnINLPMDICREATESTRUCT;       // 15  +0x78
        KernelCallbackProc fnINOUTLPMEASUREITEMSTRUCT;  // 16  +0x80
        KernelCallbackProc fnINLPWINDOWPOS;             // 17  +0x88
        KernelCallbackProc fnINOUTLPPOINT5_18;          // 18  +0x90
        KernelCallbackProc fnINOUTLPSCROLLINFO;         // 19  +0x98
        KernelCallbackProc fnINOUTLPRECT;               // 20  +0xA0
        KernelCallbackProc fnINOUTNCCALCSIZE;           // 21  +0xA8
        KernelCallbackProc fnINOUTLPPOINT5_22;          // 22  +0xB0
        KernelCallbackProc fnINPAINTCLIPBRD;            // 23  +0xB8
        KernelCallbackProc fnINSIZECLIPBRD;             // 24  +0xC0
        KernelCallbackProc fnINDESTROYCLIPBRD;          // 25  +0xC8
        KernelCallbackProc fnINSTRING_26;               // 26  +0xD0
        KernelCallbackProc fnINSTRING_27;               // 27  +0xD8
        KernelCallbackProc fnINDEVICECHANGE;            // 28  +0xE0
        KernelCallbackProc fnPOWERBROADCAST;            // 29  +0xE8
        KernelCallbackProc fnINOUTNEXTMENU;             // 30  +0xF0
        KernelCallbackProc fnOUTDWORDDWORD_31;          // 31  +0xF8
        KernelCallbackProc fnOUTDWORDDWORD_32;          // 32  +0x100
        KernelCallbackProc fnOUTDWORDINDWORD;           // 33  +0x108
        KernelCallbackProc fnOUTLPRECT;                 // 34  +0x110
        KernelCallbackProc fnINCNTOUTSTRINGNULL_35;     // 35  +0x118
        KernelCallbackProc fnINPGESTURENOTIFYSTRUCT_36; // 36  +0x120
        KernelCallbackProc fnINCNTOUTSTRINGNULL_37;     // 37  +0x128
        KernelCallbackProc fnSENTDDEMSG;                // 38  +0x130
        KernelCallbackProc fnINOUTSTYLECHANGE;          // 39  +0x138
        KernelCallbackProc fnHkINDWORD;                 // 40  +0x140
        KernelCallbackProc fnHkINLPCBTACTIVATESTRUCT;   // 41  +0x148
        KernelCallbackProc fnHkINLPCBTCREATESTRUCT;     // 42  +0x150
        KernelCallbackProc fnHkINLPDEBUGHOOKSTRUCT;     // 43  +0x158
        KernelCallbackProc fnHkINLPMOUSEHOOKSTRUCTEX;   // 44  +0x160
        KernelCallbackProc fnHkINLPKBDLLHOOKSTRUCT;     // 45  +0x168
        KernelCallbackProc fnHkINLPMSLLHOOKSTRUCT;      // 46  +0x170
        KernelCallbackProc fnHkINLPMSG;                 // 47  +0x178
        KernelCallbackProc fnHkINLPRECT;                // 48  +0x180
        KernelCallbackProc fnHkOPTINLPEVENTMSG;         // 49  +0x188
        KernelCallbackProc ClientCopyDDEIn1;            // 50  +0x190
        KernelCallbackProc ClientCopyDDEIn2;            // 51  +0x198
        KernelCallbackProc ClientCopyDDEOut1;           // 52  +0x1A0
        KernelCallbackProc ClientCopyDDEOut2;           // 53  +0x1A8
        KernelCallbackProc ClientCopyImage;             // 54  +0x1B0
        KernelCallbackProc ClientEventCallback;         // 55  +0x1B8
        KernelCallbackProc ClientFindMnemChar;          // 56  +0x1C0
        KernelCallbackProc ClientFreeDDEHandle;         // 57  +0x1C8
        KernelCallbackProc ClientFreeLibrary;           // 58  +0x1D0
        KernelCallbackProc ClientGetCharsetInfo;        // 59  +0x1D8
        KernelCallbackProc ClientGetDDEFlags;           // 60  +0x1E0
        KernelCallbackProc ClientGetDDEHookData;        // 61  +0x1E8
        KernelCallbackProc ClientGetListboxString;      // 62  +0x1F0
        KernelCallbackProc ClientGetMessageMPH;         // 63  +0x1F8
        KernelCallbackProc ClientLoadImage;             // 64  +0x200
        KernelCallbackProc ClientLoadLibrary;           // 65  +0x208
        KernelCallbackProc ClientLoadMenu;              // 66  +0x210
        KernelCallbackProc ClientLoadLocalT1Fonts;      // 67  +0x218
        KernelCallbackProc ClientPSMTextOut;            // 68  +0x220
        KernelCallbackProc ClientLpkDrawTextEx;         // 69  +0x228
        KernelCallbackProc ClientExtTextOutW;           // 70  +0x230
        KernelCallbackProc ClientGetTextExtentPointW;   // 71  +0x238
        KernelCallbackProc ClientCharToWchar;           // 72  +0x240
        KernelCallbackProc ClientAddFontResourceW;      // 73  +0x248
        KernelCallbackProc ClientThreadSetup;           // 74  +0x250
        KernelCallbackProc ClientDeliverUserApc;        // 75  +0x258
        KernelCallbackProc ClientNoMemoryPopup;         // 76  +0x260
        KernelCallbackProc ClientMonitorEnumProc;       // 77  +0x268
        KernelCallbackProc ClientCallWinEventProc;      // 78  +0x270
        KernelCallbackProc ClientWaitMessageExMPH;      // 79  +0x278
        KernelCallbackProc ClientWOWGetProcModule;      // 80  +0x280
        KernelCallbackProc ClientWOWTask16SchedNotify;  // 81  +0x288
        KernelCallbackProc ClientImmLoadLayout;         // 82  +0x290
        KernelCallbackProc ClientImmProcessKey;         // 83  +0x298
        KernelCallbackProc fnIMECONTROL;                // 84  +0x2A0
        KernelCallbackProc fnINWPARAMDBCSCHAR;          // 85  +0x2A8
        KernelCallbackProc fnGETTEXTLENGTHS_86;         // 86  +0x2B0
        KernelCallbackProc fnINLPKDRAWSWITCHWND;        // 87  +0x2B8
        KernelCallbackProc ClientLoadStringW;           // 88  +0x2C0
        KernelCallbackProc ClientLoadOLE;               // 89  +0x2C8
        KernelCallbackProc ClientRegisterDragDrop;      // 90  +0x2D0
        KernelCallbackProc ClientRevokeDragDrop;        // 91  +0x2D8
        KernelCallbackProc fnINOUTMENUGETOBJECT;        // 92  +0x2E0
        KernelCallbackProc ClientPrinterThunk;          // 93  +0x2E8
        KernelCallbackProc fnOUTLPCOMBOBOXINFO;         // 94  +0x2F0
        KernelCallbackProc fnOUTLPSCROLLBARINFO;        // 95  +0x2F8
        KernelCallbackProc fnINOUTNEXTMENU_96;          // 96  +0x300
        KernelCallbackProc fnINLPUAHDRAWMENUITEM;       // 97  +0x308
        KernelCallbackProc fnINOUTNEXTMENU_98;          // 98  +0x310
        KernelCallbackProc fnINOUTLPUAHMEASUREMENUITEM; // 99  +0x318
        KernelCallbackProc fnINOUTNEXTMENU_100;         // 100  +0x320
        KernelCallbackProc fnOUTLPTITLEBARINFOEX;       // 101  +0x328
        KernelCallbackProc fnTOUCH;                     // 102  +0x330
        KernelCallbackProc fnGESTURE;                   // 103  +0x338
        KernelCallbackProc fnINPGESTURENOTIFYSTRUCT_104;// 104  +0x340
        KernelCallbackProc null_105;                    // 105  +0x348
        KernelCallbackProc ButtonWndProcWorker;         // 106  +0x350
        KernelCallbackProc ComboBoxWndProcWorker;       // 107  +0x358
        KernelCallbackProc ListBoxWndProcWorker_108;    // 108  +0x360
        KernelCallbackProc DefDlgProcWorker;            // 109  +0x368
        KernelCallbackProc EditWndProcWorker;           // 110  +0x370
        KernelCallbackProc ListBoxWndProcWorker_111;    // 111  +0x378
        KernelCallbackProc MDIClientWndProcWorker;      // 112  +0x380
        KernelCallbackProc StaticWndProcWorker;         // 113  +0x388
        KernelCallbackProc ImeWndProcWorker;            // 114  +0x390
        KernelCallbackProc DefWindowProcWorker;         // 115  +0x398
        KernelCallbackProc CtfHookProcWorker;           // 116  +0x3A0
        KernelCallbackProc null_117;                    // 117  +0x3A8
        KernelCallbackProc null_118;                    // 118  +0x3B0
        KernelCallbackProc null_119;                    // 119  +0x3B8
        KernelCallbackProc ScrollBarWndProcW;           // 120  +0x3C0
        KernelCallbackProc DefWindowProcW_121;          // 121  +0x3C8
        KernelCallbackProc MenuWndProcW;                // 122  +0x3D0
        KernelCallbackProc DesktopWndProcW;             // 123  +0x3D8
        KernelCallbackProc DefWindowProcW_124;          // 124  +0x3E0
        KernelCallbackProc DefWindowProcW_125;          // 125  +0x3E8
        KernelCallbackProc DefWindowProcW_126;          // 126  +0x3F0
        KernelCallbackProc ButtonWndProcW_127;          // 127  +0x3F8
        KernelCallbackProc ComboBoxWndProcW;            // 128  +0x400
        KernelCallbackProc ListBoxWndProcW_129;         // 129  +0x408
        KernelCallbackProc DefDlgProcW;                 // 130  +0x410
        KernelCallbackProc EditWndProcW;                // 131  +0x418
        KernelCallbackProc ListBoxWndProcW_132;         // 132  +0x420
        KernelCallbackProc MDIClientWndProcW;           // 133  +0x428
        KernelCallbackProc StaticWndProcW;              // 134  +0x430
        KernelCallbackProc ImeWndProcW;                 // 135  +0x438
        KernelCallbackProc DefWindowProcW;              // 136  +0x440
        KernelCallbackProc fnHkINLPCWPSTRUCTW;          // 137  +0x448
        KernelCallbackProc fnHkINLPCWPRETSTRUCTW;       // 138  +0x450
        KernelCallbackProc DispatchHookW;               // 139  +0x458
        KernelCallbackProc DispatchDefWindowProcW;      // 140  +0x460
        KernelCallbackProc DispatchClientMessage;       // 141  +0x468
        KernelCallbackProc MDIActivateDlgProcW_142;     // 142  +0x470
        KernelCallbackProc null_167;                    // 143  +0x478
        KernelCallbackProc ScrollBarWndProcA;           // 144  +0x480
        KernelCallbackProc DefWindowProcA_145;          // 145  +0x488
        KernelCallbackProc MenuWndProcA;                // 146  +0x490
        KernelCallbackProc DesktopWndProcA;             // 147  +0x498
        KernelCallbackProc DefWindowProcA_148;          // 148  +0x4A0
        KernelCallbackProc DefWindowProcA_149;          // 149  +0x4A8
        KernelCallbackProc DefWindowProcA_150;          // 150  +0x4B0
        KernelCallbackProc ButtonWndProcA_151;          // 151  +0x4B8
        KernelCallbackProc ComboBoxWndProcA;            // 152  +0x4C0
        KernelCallbackProc ListBoxWndProcA_153;         // 153  +0x4C8
        KernelCallbackProc DefDlgProcA;                 // 154  +0x4D0
        KernelCallbackProc EditWndProcA;                // 155  +0x4D8
        KernelCallbackProc ListBoxWndProcA_156;         // 156  +0x4E0
        KernelCallbackProc MDIClientWndProcA;           // 157  +0x4E8
        KernelCallbackProc StaticWndProcA;              // 158  +0x4F0
        KernelCallbackProc ImeWndProcA;                 // 159  +0x4F8
        KernelCallbackProc DefWindowProcA;              // 160  +0x500
        KernelCallbackProc fnHkINLPCWPSTRUCTA;          // 161  +0x508
        KernelCallbackProc fnHkINLPCWPRETSTRUCTA;       // 162  +0x510
        KernelCallbackProc DispatchHookA;               // 163  +0x518
        KernelCallbackProc DispatchDefWindowProcA;      // 164  +0x520
        KernelCallbackProc DispatchClientMessage_165;	// 165  +0x528
        KernelCallbackProc MDIActivateDlgProcW_166;     // 166  +0x530

    } KERNEL_CALLBACK_TABLE_64;

    typedef struct _PEB64
    {
        union
        {
            struct
            {
                uint8_t InheritedAddressSpace;
                uint8_t ReadImageFileExecOptions;
                uint8_t BeingDebugged;

                union
                {
                    uint8_t BitField;

                    struct
                    {
                        uint8_t ImageUsesLargePages : 1;
                        uint8_t IsProtectedProcess : 1;
                        uint8_t IsImageDynamicallyRelocated : 1;
                        uint8_t SkipPatchingUser32Forwarders : 1;
                        uint8_t IsPackagedProcess : 1;
                        uint8_t IsAppContainer : 1;
                        uint8_t IsProtectedProcessLight : 1;
                        uint8_t SpareBits : 1;
                    };
                };
            };

            PTR_64/* PVOID */ Data00;
        };

        PTR_64/* HANDLE */ Mutant;
        PTR_64/* PVOID */ ImageBaseAddress;
        PTR_64/* PPEB_LDR_DATA */ Ldr;
        PTR_64/* PRTL_USER_PROCESS_PARAMETERS */ ProcessParameters;
        PTR_64/* PVOID */ SubSystemData;
        PTR_64/* PVOID */ ProcessHeap;
        PTR_64/* PRTL_CRITICAL_SECTION */ FastPebLock;
        PTR_64/* PVOID */ _SYSTEM_DEPENDENT_02;
        PTR_64/* PVOID */ _SYSTEM_DEPENDENT_03;
        PTR_64/* PVOID */ _SYSTEM_DEPENDENT_04;

        union
        {
            PTR_64/* PVOID */ KernelCallbackTable;
            PTR_64/* PVOID */ UserSharedInfoPtr;
        };

        ulong_t SystemReserved;
        ulong_t SpareUlong;

        PTR_64/* PPEB_FREE_BLOCK */ FreeList;
        PTR_64/* ULONG */ TlsExpansionCounter;
        PTR_64/* PVOID */ TlsBitmap;

        ulong_t TlsBitmapBits[ 2 ];

        PTR_64/* PVOID */ ReadOnlySharedMemoryBase;
        PTR_64/* PVOID */ ReadOnlySharedMemoryHeap;
        PTR_64/* PVOID */ ReadOnlyStaticServerData;
        PTR_64/* PVOID */ AnsiCodePageData;
        PTR_64/* PVOID */ OemCodePageData;
        PTR_64/* PVOID */ UnicodeCaseTableData;

        ulong_t NumberOfProcessors;
        ulong_t NtGlobalFlag;

        LARGE_INTEGER CriticalSectionTimeout;

        PTR_64/* SIZE_T */ HeapSegmentReserve;
        PTR_64/* SIZE_T */ HeapSegmentCommit;
        PTR_64/* SIZE_T */ HeapDeCommitTotalFreeThreshold;
        PTR_64/* SIZE_T */ HeapDeCommitFreeBlockThreshold;

        ulong_t NumberOfHeaps;
        ulong_t MaximumNumberOfHeaps;

        PTR_64/* PPVOID */ ProcessHeaps;
        PTR_64/* PVOID */ GdiSharedHandleTable;
        PTR_64/* PVOID */ ProcessStarterHelper;
        PTR_64/* PVOID */ GdiDCAttributeList;
        PTR_64/* PRTL_CRITICAL_SECTION */ LoaderLock;

        ulong_t OSMajorVersion;
        ulong_t OSMinorVersion;
        ushort_t OSBuildNumber;
        ushort_t OSCSDVersion;
        ulong_t OSPlatformId;
        ulong_t ImageSubsystem;
        ulong_t ImageSubsystemMajorVersion;
        ulong_t ImageSubsystemMinorVersion;

    } PEB64, * PPEB64;

#pragma pack(pop)
#pragma pack(push, 4)

    typedef struct _PEB_LDR_DATA32
    {
        ulong_t Length;

        union
        {
            uint8_t Initialized;
            ulong_t Data00;
        };

        PTR_32/* HANDLE */	SsHandle;
        LIST_ENTRY32		InLoadOrderModuleList;
        LIST_ENTRY32		InMemoryOrderModuleList;
        LIST_ENTRY32		InInitializationOrderModuleList;
        PTR_32/* PVOID */	EntryInProgress;

    } PEB_LDR_DATA32, * PPEB_LDR_DATA32;

#pragma pack(pop)
#pragma pack(push, 4)

    typedef struct _PEB_LDR_DATA64
    {
        ulong_t Length;

        union
        {
            uint8_t Initialized;
            ulong_t Data00;
        };

        PTR_64/* HANDLE */	SsHandle;
        LIST_ENTRY64		InLoadOrderModuleList;
        LIST_ENTRY64		InMemoryOrderModuleList;
        LIST_ENTRY64		InInitializationOrderModuleList;
        PTR_64/* PVOID */	EntryInProgress;

    } PEB_LDR_DATA64, * PPEB_LDR_DATA64;

#pragma pack(pop)

    /****************************************************************************

        structures and defines -- Thread context

    ****************************************************************************/

#define SIZE_OF_80387_REGISTERS			80
#define MAXIMUM_SUPPORTED_EXTENSION     512

    typedef XSAVE_FORMAT XMM_SAVE_AREA32, * PXMM_SAVE_AREA32;

#if defined(_WIN64)

    typedef struct _FLOATING_SAVE_AREA
    {
        DWORD   ControlWord;
        DWORD   StatusWord;
        DWORD   TagWord;
        DWORD   ErrorOffset;
        DWORD   ErrorSelector;
        DWORD   DataOffset;
        DWORD   DataSelector;
        BYTE    RegisterArea[ SIZE_OF_80387_REGISTERS ];
        DWORD   Spare0;

    } FLOATING_SAVE_AREA;

#else

#define INITIAL_MXCSR		0x1f80  // initial MXCSR value
#define INITIAL_FPCSR		0x027f  // initial FPCSR value
#define KGDT64_R3_CODE		0x0030  // user mode 64-bit code
#define KGDT64_R3_DATA		0x0028
#define KGDT64_R3_CMTEB		0x0050

#endif

#define KGDT32_R3_CODE 0x20

    typedef struct DECLSPEC_ALIGN( 16 ) _CONTEXT64
    {

        //
        // Register parameter home addresses.
        //
        // N.B. These fields are for convience - they could be used to extend the
        //      context record in the future.
        //

        DWORD64 P1Home;
        DWORD64 P2Home;
        DWORD64 P3Home;
        DWORD64 P4Home;
        DWORD64 P5Home;
        DWORD64 P6Home;

        //
        // Control flags.
        //

        DWORD ContextFlags;
        DWORD MxCsr;

        //
        // Segment Registers and processor flags.
        //

        WORD   SegCs;
        WORD   SegDs;
        WORD   SegEs;
        WORD   SegFs;
        WORD   SegGs;
        WORD   SegSs;
        DWORD EFlags;

        //
        // Debug registers
        //

        DWORD64 Dr0;
        DWORD64 Dr1;
        DWORD64 Dr2;
        DWORD64 Dr3;
        DWORD64 Dr6;
        DWORD64 Dr7;

        //
        // Integer registers.
        //

        DWORD64 Rax;
        DWORD64 Rcx;
        DWORD64 Rdx;
        DWORD64 Rbx;
        DWORD64 Rsp;
        DWORD64 Rbp;
        DWORD64 Rsi;
        DWORD64 Rdi;
        DWORD64 R8;
        DWORD64 R9;
        DWORD64 R10;
        DWORD64 R11;
        DWORD64 R12;
        DWORD64 R13;
        DWORD64 R14;
        DWORD64 R15;

        //
        // Program counter.
        //

        DWORD64 Rip;

        //
        // Floating point state.
        //

        union {
            XMM_SAVE_AREA32 FltSave;
            struct {
                M128A Header[ 2 ];
                M128A Legacy[ 8 ];
                M128A Xmm0;
                M128A Xmm1;
                M128A Xmm2;
                M128A Xmm3;
                M128A Xmm4;
                M128A Xmm5;
                M128A Xmm6;
                M128A Xmm7;
                M128A Xmm8;
                M128A Xmm9;
                M128A Xmm10;
                M128A Xmm11;
                M128A Xmm12;
                M128A Xmm13;
                M128A Xmm14;
                M128A Xmm15;
            } DUMMYSTRUCTNAME;
        } DUMMYUNIONNAME;

        //
        // Vector registers.
        //

        M128A VectorRegister[ 26 ];
        DWORD64 VectorControl;

        //
        // Special debug control registers.
        //

        DWORD64 DebugControl;
        DWORD64 LastBranchToRip;
        DWORD64 LastBranchFromRip;
        DWORD64 LastExceptionToRip;
        DWORD64 LastExceptionFromRip;

    } CONTEXT64, * PCONTEXT64;

    typedef struct _CONTEXT32
    {

        //
        // The flags values within this flag control the contents of
        // a CONTEXT record.
        //
        // If the context record is used as an input parameter, then
        // for each portion of the context record controlled by a flag
        // whose value is set, it is assumed that that portion of the
        // context record contains valid context. If the context record
        // is being used to modify a threads context, then only that
        // portion of the threads context will be modified.
        //
        // If the context record is used as an IN OUT parameter to capture
        // the context of a thread, then only those portions of the thread's
        // context corresponding to set flags will be returned.
        //
        // The context record is never used as an OUT only parameter.
        //

        DWORD ContextFlags;

        //
        // This section is specified/returned if CONTEXT_DEBUG_REGISTERS is
        // set in ContextFlags.  Note that CONTEXT_DEBUG_REGISTERS is NOT
        // included in CONTEXT_FULL.
        //

        DWORD   Dr0;
        DWORD   Dr1;
        DWORD   Dr2;
        DWORD   Dr3;
        DWORD   Dr6;
        DWORD   Dr7;

        //
        // This section is specified/returned if the
        // ContextFlags word contians the flag CONTEXT_FLOATING_POINT.
        //

        FLOATING_SAVE_AREA FloatSave;

        //
        // This section is specified/returned if the
        // ContextFlags word contians the flag CONTEXT_SEGMENTS.
        //

        DWORD   SegGs;
        DWORD   SegFs;
        DWORD   SegEs;
        DWORD   SegDs;

        //
        // This section is specified/returned if the
        // ContextFlags word contians the flag CONTEXT_INTEGER.
        //

        DWORD   Edi;
        DWORD   Esi;
        DWORD   Ebx;
        DWORD   Edx;
        DWORD   Ecx;
        DWORD   Eax;

        //
        // This section is specified/returned if the
        // ContextFlags word contians the flag CONTEXT_CONTROL.
        //

        DWORD   Ebp;
        DWORD   Eip;
        DWORD   SegCs;              // MUST BE SANITIZED
        DWORD   EFlags;             // MUST BE SANITIZED
        DWORD   Esp;
        DWORD   SegSs;

        //
        // This section is specified/returned if the ContextFlags word
        // contains the flag CONTEXT_EXTENDED_REGISTERS.
        // The format and contexts are processor specific
        //

        BYTE    ExtendedRegisters[ MAXIMUM_SUPPORTED_EXTENSION ];

    } CONTEXT32, * PCONTEXT32;

#if 0

    typedef struct _WOW64_CONTEXT
    {
        //
        // The flags values within this flag control the contents of
        // a CONTEXT record.
        //
        // If the context record is used as an input parameter, then
        // for each portion of the context record controlled by a flag
        // whose value is set, it is assumed that that portion of the
        // context record contains valid context. If the context record
        // is being used to modify a threads context, then only that
        // portion of the threads context will be modified.
        //
        // If the context record is used as an IN OUT parameter to capture
        // the context of a thread, then only those portions of the thread's
        // context corresponding to set flags will be returned.
        //
        // The context record is never used as an OUT only parameter.
        //

        DWORD ContextFlags;

        //
        // This section is specified/returned if CONTEXT_DEBUG_REGISTERS is
        // set in ContextFlags.  Note that CONTEXT_DEBUG_REGISTERS is NOT
        // included in CONTEXT_FULL.
        //

        DWORD   Dr0;
        DWORD   Dr1;
        DWORD   Dr2;
        DWORD   Dr3;
        DWORD   Dr6;
        DWORD   Dr7;

        //
        // This section is specified/returned if the
        // ContextFlags word contians the flag CONTEXT_FLOATING_POINT.
        //

        WOW64_FLOATING_SAVE_AREA FloatSave;

        //
        // This section is specified/returned if the
        // ContextFlags word contians the flag CONTEXT_SEGMENTS.
        //

        DWORD   SegGs;
        DWORD   SegFs;
        DWORD   SegEs;
        DWORD   SegDs;

        //
        // This section is specified/returned if the
        // ContextFlags word contians the flag CONTEXT_INTEGER.
        //

        DWORD   Edi;
        DWORD   Esi;
        DWORD   Ebx;
        DWORD   Edx;
        DWORD   Ecx;
        DWORD   Eax;

        //
        // This section is specified/returned if the
        // ContextFlags word contians the flag CONTEXT_CONTROL.
        //

        DWORD   Ebp;
        DWORD   Eip;
        DWORD   SegCs;              // MUST BE SANITIZED
        DWORD   EFlags;             // MUST BE SANITIZED
        DWORD   Esp;
        DWORD   SegSs;

        //
        // This section is specified/returned if the ContextFlags word
        // contains the flag CONTEXT_EXTENDED_REGISTERS.
        // The format and contexts are processor specific
        //

        BYTE    ExtendedRegisters[ WOW64_MAXIMUM_SUPPORTED_EXTENSION ];

    } WOW64_CONTEXT, * PWOW64_CONTEXT;

#endif

    /****************************************************************************

        structures and defines -- Heap

    ****************************************************************************/

#define HEAP_GRANULARITY            ((LONG) sizeof( HEAP_ENTRY ))
#if defined(_WIN64)
#define HEAP_GRANULARITY_SHIFT      4   // Log2( HEAP_GRANULARITY )
#else
#define HEAP_GRANULARITY_SHIFT		3   // Log2( HEAP_GRANULARITY )
#endif

#define HEAP_MAXIMUM_FREELISTS					128
#define HEAP_MAXIMUM_SEGMENTS					64

#define HEAP_SIGNATURE							(ULONG)0xEEFFEEFF
#define HEAP_LOCK_USER_ALLOCATED				(ULONG)0x80000000
#define HEAP_VALIDATE_PARAMETERS_ENABLED		(ULONG)0x40000000
#define HEAP_VALIDATE_ALL_ENABLED				(ULONG)0x20000000
#define HEAP_SKIP_VALIDATION_CHECKS				(ULONG)0x10000000
#define HEAP_CAPTURE_STACK_BACKTRACES			(ULONG)0x08000000
#define HEAP_SEGMENT_SIGNATURE					0xFFEEFFEE
#define HEAP_SEGMENT_USER_ALLOCATED				(ULONG)0x00000001
#define CHECK_HEAP_TAIL_SIZE					HEAP_GRANULARITY
#define CHECK_HEAP_TAIL_FILL					0xAB
#define FREE_HEAP_FILL							0xFEEEFEEE
#define ALLOC_HEAP_FILL							0xBAADF00D

#pragma pack(push, 4)

    typedef struct _HEAP_ENTRY
    {
        //
        //  This field gives the size of the current block in allocation
        //  granularity units.  (i.e. Size << HEAP_GRANULARITY_SHIFT
        //  equals the size in bytes).
        //
        //  Except if this is part of a virtual alloc block then this
        //  value is the difference between the commit size in the virtual
        //  alloc entry and the what the user asked for.
        //

        USHORT Size;

        //
        // This field gives the size of the previous block in allocation
        // granularity units. (i.e. PreviousSize << HEAP_GRANULARITY_SHIFT
        // equals the size of the previous block in bytes).
        //

        USHORT PreviousSize;

        //
        // This field contains the index into the segment that controls
        // the memory for this block.
        //

        UCHAR SegmentIndex;

        //
        // This field contains various flag bits associated with this block.
        // Currently these are:
        //
        //  0x01 - HEAP_ENTRY_BUSY
        //  0x02 - HEAP_ENTRY_EXTRA_PRESENT
        //  0x04 - HEAP_ENTRY_FILL_PATTERN
        //  0x08 - HEAP_ENTRY_VIRTUAL_ALLOC
        //  0x10 - HEAP_ENTRY_LAST_ENTRY
        //  0x20 - HEAP_ENTRY_SETTABLE_FLAG1
        //  0x40 - HEAP_ENTRY_SETTABLE_FLAG2
        //  0x80 - HEAP_ENTRY_SETTABLE_FLAG3
        //

        UCHAR Flags;

        //
        // This field contains the number of unused bytes at the end of this
        // block that were not actually allocated.  Used to compute exact
        // size requested prior to rounding requested size to allocation
        // granularity.  Also used for tail checking purposes.
        //

        UCHAR UnusedBytes;

        //
        // Small (8 bit) tag indexes can go here.
        //

        UCHAR SmallTagIndex;

#if defined(_WIN64)
        ULONGLONG Reserved1;
#endif

    } HEAP_ENTRY, * PHEAP_ENTRY;

    typedef struct _HEAP_SEGMENT
    {
        HEAP_ENTRY Entry;

        ULONG Signature;
        ULONG Flags;
        struct _HEAP* Heap;
        SIZE_T LargestUnCommittedRange;

        PVOID BaseAddress;
        ULONG NumberOfPages;
        PHEAP_ENTRY FirstEntry;
        PHEAP_ENTRY LastValidEntry;

        ULONG NumberOfUnCommittedPages;
        ULONG NumberOfUnCommittedRanges;

        PVOID/*PHEAP_UNCOMMMTTED_RANGE*/ UnCommittedRanges;

        USHORT AllocatorBackTraceIndex;
        USHORT Reserved;
        PHEAP_ENTRY LastEntryInSegment;

    } HEAP_SEGMENT, * PHEAP_SEGMENT;

    typedef struct _HEAP_LOCK
    {
        union
        {
            RTL_CRITICAL_SECTION CriticalSection;
        } Lock;

    } HEAP_LOCK, * PHEAP_LOCK;

    typedef struct _HEAP_UCR_SEGMENT
    {
        struct _HEAP_UCR_SEGMENT* Next;
        SIZE_T ReservedSize;
        SIZE_T CommittedSize;
        ULONG filler;

    } HEAP_UCR_SEGMENT, * PHEAP_UCR_SEGMENT;

    typedef struct _HEAP_TAG_ENTRY
    {
        ULONG Allocs;
        ULONG Frees;
        SIZE_T Size;
        USHORT TagIndex;
        USHORT CreatorBackTraceIndex;
        WCHAR TagName[ 24 ];

    } HEAP_TAG_ENTRY, * PHEAP_TAG_ENTRY;

    typedef struct _HEAP
    {
        HEAP_ENTRY Entry;

        ULONG Signature;
        ULONG Flags;
        ULONG ForceFlags;
        ULONG VirtualMemoryThreshold;

        SIZE_T SegmentReserve;
        SIZE_T SegmentCommit;
        SIZE_T DeCommitFreeBlockThreshold;
        SIZE_T DeCommitTotalFreeThreshold;

        SIZE_T TotalFreeSize;
        SIZE_T MaximumAllocationSize;
        USHORT ProcessHeapsListIndex;
        USHORT HeaderValidateLength;
        PVOID HeaderValidateCopy;

        USHORT NextAvailableTagIndex;
        USHORT MaximumTagIndex;
        PHEAP_TAG_ENTRY TagEntries;
        PHEAP_UCR_SEGMENT UCRSegments;
        PVOID/*PHEAP_UNCOMMMTTED_RANGE*/ UnusedUnCommittedRanges;

        //
        //  The following two fields control the alignment for each new heap entry
        //  allocation.  The round is added to each size and the mask is used to
        //  align it.  The round value includes the heap entry and any tail checking
        //  space
        //

        ULONG AlignRound;
        ULONG AlignMask;

        LIST_ENTRY VirtualAllocdBlocks;

        PHEAP_SEGMENT Segments[ HEAP_MAXIMUM_SEGMENTS ];

        union {
            ULONG FreeListsInUseUlong[ HEAP_MAXIMUM_FREELISTS / 32 ];
            UCHAR FreeListsInUseBytes[ HEAP_MAXIMUM_FREELISTS / 8 ];
        } u;

        USHORT FreeListsInUseTerminate;
        USHORT AllocatorBackTraceIndex;
        ULONG Reserved1[ 2 ];
        PVOID/*PHEAP_PSEUDO_TAG_ENTRY*/ PseudoTagEntries;

        LIST_ENTRY FreeLists[ HEAP_MAXIMUM_FREELISTS ];

        PHEAP_LOCK LockVariable;
        PRTL_HEAP_COMMIT_ROUTINE CommitRoutine;

        //
        //  The following field is used to manage the heap lookaside list.  The
        //  pointer is used to locate the lookaside list array.  If it is null
        //  then the lookaside list is not active.
        //
        //  The lock count is used to denote if the heap is locked.  A zero value
        //  means the heap is not locked.  Each lock operation increments the
        //  heap count and each unlock decrements the counter
        //

        PVOID Lookaside;
        ULONG LookasideLockCount;

    } HEAP, * PHEAP;


#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif //_PROC_H_