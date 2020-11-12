#pragma once

#include "Native/NativeStructs.h"

#define PTR_ADD_OFFSET(Pointer, Offset) ((PVOID)((ULONG_PTR)(Pointer) + (ULONG_PTR)(Offset)))
#define PTR_SUB_OFFSET(Pointer, Offset) ((PVOID)((ULONG_PTR)(Pointer) - (ULONG_PTR)(Offset)))

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

extern "C" {

typedef struct _KNONVOLATILE_CONTEXT_POINTERS
{
	union
	{
		PM128A FloatingContext[16];
		struct
		{
			PM128A Xmm0;
			PM128A Xmm1;
			PM128A Xmm2;
			PM128A Xmm3;
			PM128A Xmm4;
			PM128A Xmm5;
			PM128A Xmm6;
			PM128A Xmm7;
			PM128A Xmm8;
			PM128A Xmm9;
			PM128A Xmm10;
			PM128A Xmm11;
			PM128A Xmm12;
			PM128A Xmm13;
			PM128A Xmm14;
			PM128A Xmm15;
		};
	};

	union
	{
		PULONG64 IntegerContext[16];
		struct
		{
			PULONG64 Rax;
			PULONG64 Rcx;
			PULONG64 Rdx;
			PULONG64 Rbx;
			PULONG64 Rsp;
			PULONG64 Rbp;
			PULONG64 Rsi;
			PULONG64 Rdi;
			PULONG64 R8;
			PULONG64 R9;
			PULONG64 R10;
			PULONG64 R11;
			PULONG64 R12;
			PULONG64 R13;
			PULONG64 R14;
			PULONG64 R15;
		};
	};
} KNONVOLATILE_CONTEXT_POINTERS, *PKNONVOLATILE_CONTEXT_POINTERS;

typedef struct _RUNTIME_FUNCTION
{
	ULONG BeginAddress;
	ULONG EndAddress;
	ULONG UnwindData;
} RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;

#define UNWIND_HISTORY_TABLE_SIZE 12

typedef struct _UNWIND_HISTORY_TABLE_ENTRY
{
	ULONG64 ImageBase;
	PRUNTIME_FUNCTION FunctionEntry;
} UNWIND_HISTORY_TABLE_ENTRY, *PUNWIND_HISTORY_TABLE_ENTRY;

typedef struct _UNWIND_HISTORY_TABLE
{
	ULONG Count;
	UCHAR Search;
	ULONG64 LowAddress;
	ULONG64 HighAddress;
	UNWIND_HISTORY_TABLE_ENTRY Entry[UNWIND_HISTORY_TABLE_SIZE];
} UNWIND_HISTORY_TABLE, *PUNWIND_HISTORY_TABLE;

typedef enum _PORT_INFORMATION_CLASS
{
	PortBasicInformation,
	PortDumpInformation
} PORT_INFORMATION_CLASS;

typedef enum _EVENT_INFORMATION_CLASS
{
	EventBasicInformation
} EVENT_INFORMATION_CLASS;

typedef enum _SEMAPHORE_INFORMATION_CLASS
{
	SemaphoreBasicInformation
} SEMAPHORE_INFORMATION_CLASS;

typedef enum _MUTANT_INFORMATION_CLASS
{
	MutantBasicInformation,
	MutantOwnerInformation
} MUTANT_INFORMATION_CLASS;

typedef enum _TIMER_INFORMATION_CLASS
{
	TimerBasicInformation
} TIMER_INFORMATION_CLASS;

typedef struct _TIMER_BASIC_INFORMATION
{
	LARGE_INTEGER RemainingTime;
	BOOLEAN TimerState;
} TIMER_BASIC_INFORMATION, *PTIMER_BASIC_INFORMATION;

typedef VOID(NTAPI *PTIMER_APC_ROUTINE)(
	_In_ PVOID TimerContext,
	_In_ ULONG TimerLowValue,
	_In_ LONG TimerHighValue
	);

typedef struct _MUTANT_BASIC_INFORMATION
{
	LONG CurrentCount;
	BOOLEAN OwnedByCaller;
	BOOLEAN AbandonedState;
} MUTANT_BASIC_INFORMATION, *PMUTANT_BASIC_INFORMATION;

typedef struct _MUTANT_OWNER_INFORMATION
{
	CLIENT_ID ClientId;
} MUTANT_OWNER_INFORMATION, *PMUTANT_OWNER_INFORMATION;

typedef struct _EVENT_BASIC_INFORMATION
{
	EVENT_TYPE EventType;
	LONG EventState;
} EVENT_BASIC_INFORMATION, *PEVENT_BASIC_INFORMATION;

typedef struct _FILE_IO_COMPLETION_INFORMATION
{
	PVOID KeyContext;
	PVOID ApcContext;
	IO_STATUS_BLOCK IoStatusBlock;
} FILE_IO_COMPLETION_INFORMATION, *PFILE_IO_COMPLETION_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR PageDirectoryBase;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

#define IO_COMPLETION_QUERY_STATE	0x0001
#define IO_COMPLETION_MODIFY_STATE	0x0002
#define IO_COMPLETION_ALL_ACCESS	(STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE| \
									IO_COMPLETION_QUERY_STATE | IO_COMPLETION_MODIFY_STATE)

typedef struct _OVERLAPPED
{
	ULONG_PTR Internal;
	ULONG_PTR InternalHigh;
	union
	{
		struct
		{
			ULONG Offset;
			ULONG OffsetHigh;
		} s;
		PVOID Pointer;
	} u;
	HANDLE hEvent;
} OVERLAPPED, *LPOVERLAPPED;

#define PROCESS_TERMINATE					(0x0001)
#define PROCESS_CREATE_THREAD				(0x0002)
#define PROCESS_SET_SESSIONID				(0x0004)
#define PROCESS_VM_OPERATION				(0x0008)
#define PROCESS_VM_READ						(0x0010)
#define PROCESS_VM_WRITE					(0x0020)
#define PROCESS_DUP_HANDLE					(0x0040)
#define PROCESS_CREATE_PROCESS				(0x0080)
#define PROCESS_SET_QUOTA					(0x0100)
#define PROCESS_SET_INFORMATION				(0x0200)
#define PROCESS_QUERY_INFORMATION			(0x0400)
#define PROCESS_SUSPEND_RESUME				(0x0800)
#define PROCESS_QUERY_LIMITED_INFORMATION	(0x1000)
#define PROCESS_SET_LIMITED_INFORMATION		(0x2000)
#if (NTDDI_VERSION >= NTDDI_VISTA)
#define PROCESS_ALL_ACCESS					(STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
											0xFFFF)
#else
#define PROCESS_ALL_ACCESS					(STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
											0xFFF)
#endif

typedef struct _PS_ATTRIBUTE
{
	ULONG_PTR Attribute;				// PROC_THREAD_ATTRIBUTE_XXX | PROC_THREAD_ATTRIBUTE_XXX modifiers, see ProcThreadAttributeValue macro and Windows Internals 6 (372)
	SIZE_T Size;						// Size of Value or *ValuePtr
	union
	{
		ULONG_PTR Value;				// Reserve 8 bytes for data (such as a Handle or a data pointer)
		PVOID ValuePtr;					// data pointer
	};
	PSIZE_T ReturnLength;				// Either 0 or specifies size of data returned to caller via "ValuePtr"
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T TotalLength;					// sizeof(PS_ATTRIBUTE_LIST)
	PS_ATTRIBUTE Attributes[2];			// Depends on how many attribute entries should be supplied to NtCreateUserProcess
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

typedef struct _PS_MEMORY_RESERVE
{
	PVOID ReserveAddress;
	SIZE_T ReserveSize;
} PS_MEMORY_RESERVE, *PPS_MEMORY_RESERVE;

#define PS_ATTRIBUTE_NUMBER_MASK	0x0000ffff
#define PS_ATTRIBUTE_THREAD			0x00010000 // Attribute may be used with thread creation
#define PS_ATTRIBUTE_INPUT			0x00020000 // Attribute is input only
#define PS_ATTRIBUTE_ADDITIVE		0x00040000 // Attribute may be "accumulated", e.g. bitmasks, counters, etc.

typedef enum _PS_ATTRIBUTE_NUM
{
	PsAttributeParentProcess,					// in HANDLE
	PsAttributeDebugPort,						// in HANDLE
	PsAttributeToken,							// in HANDLE
	PsAttributeClientId,						// out PCLIENT_ID
	PsAttributeTebAddress,						// out PTEB
	PsAttributeImageName,						// in PWSTR
	PsAttributeImageInfo,						// out PSECTION_IMAGE_INFORMATION
	PsAttributeMemoryReserve,					// in PPS_MEMORY_RESERVE
	PsAttributePriorityClass,					// in UCHAR
	PsAttributeErrorMode,						// in ULONG
	PsAttributeStdHandleInfo,					// in PPS_STD_HANDLE_INFO
	PsAttributeHandleList,						// in PHANDLE
	PsAttributeGroupAffinity,					// in PGROUP_AFFINITY
	PsAttributePreferredNode,					// in PUSHORT
	PsAttributeIdealProcessor,					// in PPROCESSOR_NUMBER
	PsAttributeUmsThread,						// see MSDN UpdateProceThreadAttributeList (CreateProcessW) - in PUMS_CREATE_THREAD_ATTRIBUTES
	PsAttributeMitigationOptions,				// in UCHAR
	PsAttributeProtectionLevel,					// in ULONG
	PsAttributeSecureProcess,					// since THRESHOLD (Virtual Secure Mode, Device Guard)
	PsAttributeJobList,
	PsAttributeChildProcessPolicy,				// since THRESHOLD2
	PsAttributeAllApplicationPackagesPolicy,	// since REDSTONE
	PsAttributeWin32kFilter,
	PsAttributeSafeOpenPromptOriginClaim,
	PsAttributeBnoIsolation,
	PsAttributeDesktopAppPolicy,
	PsAttributeMax
} PS_ATTRIBUTE_NUM;

#define PsAttributeValue(Number, Thread, Input, Additive) \
	(((Number) & PS_ATTRIBUTE_NUMBER_MASK) | \
	((Thread) ? PS_ATTRIBUTE_THREAD : 0) | \
	((Input) ? PS_ATTRIBUTE_INPUT : 0) | \
	((Additive) ? PS_ATTRIBUTE_ADDITIVE : 0))

#define PS_ATTRIBUTE_PARENT_PROCESS \
	PsAttributeValue(PsAttributeParentProcess, FALSE, TRUE, TRUE) // 0x60000
#define PS_ATTRIBUTE_DEBUG_PORT \
	PsAttributeValue(PsAttributeDebugPort, FALSE, TRUE, TRUE) // 0x60001
#define PS_ATTRIBUTE_TOKEN \
	PsAttributeValue(PsAttributeToken, FALSE, TRUE, TRUE) // 0x60002
#define PS_ATTRIBUTE_CLIENT_ID \
	PsAttributeValue(PsAttributeClientId, TRUE, FALSE, FALSE) // 0x10003
#define PS_ATTRIBUTE_TEB_ADDRESS \
	PsAttributeValue(PsAttributeTebAddress, TRUE, FALSE, FALSE) // 0x10004
#define PS_ATTRIBUTE_IMAGE_NAME \
	PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE) // 0x20005
#define PS_ATTRIBUTE_IMAGE_INFO \
	PsAttributeValue(PsAttributeImageInfo, FALSE, FALSE, FALSE) // 0x6
#define PS_ATTRIBUTE_MEMORY_RESERVE \
	PsAttributeValue(PsAttributeMemoryReserve, FALSE, TRUE, FALSE) // 0x20007
#define PS_ATTRIBUTE_PRIORITY_CLASS \
	PsAttributeValue(PsAttributePriorityClass, FALSE, TRUE, FALSE) // 0x20008
#define PS_ATTRIBUTE_ERROR_MODE \
	PsAttributeValue(PsAttributeErrorMode, FALSE, TRUE, FALSE) // 0x20009
#define PS_ATTRIBUTE_STD_HANDLE_INFO \
	PsAttributeValue(PsAttributeStdHandleInfo, FALSE, TRUE, FALSE) // 0x2000A
#define PS_ATTRIBUTE_HANDLE_LIST \
	PsAttributeValue(PsAttributeHandleList, FALSE, TRUE, FALSE) // 0x2000B
#define PS_ATTRIBUTE_GROUP_AFFINITY \
	PsAttributeValue(PsAttributeGroupAffinity, TRUE, TRUE, FALSE) // 0x2000C
#define PS_ATTRIBUTE_PREFERRED_NODE \
	PsAttributeValue(PsAttributePreferredNode, FALSE, TRUE, FALSE) // 0x2000D
#define PS_ATTRIBUTE_IDEAL_PROCESSOR \
	PsAttributeValue(PsAttributeIdealProcessor, TRUE, TRUE, FALSE) // 0x2000E
#define PS_ATTRIBUTE_MITIGATION_OPTIONS \
	PsAttributeValue(PsAttributeMitigationOptions, FALSE, TRUE, TRUE) // 0x60010
#define PS_ATTRIBUTE_PROTECTION_LEVEL \
	PsAttributeValue(PsAttributeProtectionLevel, FALSE, TRUE, FALSE) // 0x20011

typedef enum _PS_STD_HANDLE_STATE {
	PsNeverDuplicate,
	PsRequestDuplicate, // Duplicate standard handles specified by PseudoHandleMask, and only if StdHandleSubsystemType matches the image subsystem
	PsAlwaysDuplicate, // Always duplicate standard handles
	PsMaxStdHandleStates
} PS_STD_HANDLE_STATE;

#define HANDLE_DETACHED_PROCESS		((HANDLE)-1)
#define HANDLE_CREATE_NEW_CONSOLE	((HANDLE)-2)
#define HANDLE_CREATE_NO_WINDOW		((HANDLE)-3)

#define PS_STD_INPUT_HANDLE			0x1
#define PS_STD_OUTPUT_HANDLE		0x2
#define PS_STD_ERROR_HANDLE			0x4

typedef struct _PS_STD_HANDLE_INFO
{
	union
	{
		ULONG Flags;
		struct
		{
			ULONG StdHandleState : 2; // PS_STD_HANDLE_STATE
			ULONG PseudoHandleMask : 3; // PS_STD_*
		} s;
	};
	ULONG StdHandleSubsystemType;
} PS_STD_HANDLE_INFO, *PPS_STD_HANDLE_INFO;

typedef struct _PS_BNO_ISOLATION_PARAMETERS
{
	UNICODE_STRING IsolationPrefix;
	ULONG HandleCount;
	PVOID *Handles;
	BOOLEAN IsolationEnabled;
} PS_BNO_ISOLATION_PARAMETERS, *PPS_BNO_ISOLATION_PARAMETERS;

typedef enum _PS_MITIGATION_OPTION
{
	PS_MITIGATION_OPTION_NX,
	PS_MITIGATION_OPTION_SEHOP,
	PS_MITIGATION_OPTION_FORCE_RELOCATE_IMAGES,
	PS_MITIGATION_OPTION_HEAP_TERMINATE,
	PS_MITIGATION_OPTION_BOTTOM_UP_ASLR,
	PS_MITIGATION_OPTION_HIGH_ENTROPY_ASLR,
	PS_MITIGATION_OPTION_STRICT_HANDLE_CHECKS,
	PS_MITIGATION_OPTION_WIN32K_SYSTEM_CALL_DISABLE,
	PS_MITIGATION_OPTION_EXTENSION_POINT_DISABLE,
	PS_MITIGATION_OPTION_PROHIBIT_DYNAMIC_CODE,
	PS_MITIGATION_OPTION_CONTROL_FLOW_GUARD,
	PS_MITIGATION_OPTION_BLOCK_NON_MICROSOFT_BINARIES,
	PS_MITIGATION_OPTION_FONT_DISABLE,
	PS_MITIGATION_OPTION_IMAGE_LOAD_NO_REMOTE,
	PS_MITIGATION_OPTION_IMAGE_LOAD_NO_LOW_LABEL,
	PS_MITIGATION_OPTION_IMAGE_LOAD_PREFER_SYSTEM32,
	PS_MITIGATION_OPTION_RETURN_FLOW_GUARD,
	PS_MITIGATION_OPTION_LOADER_INTEGRITY_CONTINUITY,
	PS_MITIGATION_OPTION_STRICT_CONTROL_FLOW_GUARD,
	PS_MITIGATION_OPTION_RESTRICT_SET_THREAD_CONTEXT
} PS_MITIGATION_OPTION;

typedef enum _PS_CREATE_STATE
{
	PsCreateInitialState,
	PsCreateFailOnFileOpen,
	PsCreateFailOnSectionCreate,
	PsCreateFailExeFormat,
	PsCreateFailMachineMismatch,
	PsCreateFailExeName, // Debugger specified
	PsCreateSuccess,
	PsCreateMaximumStates
} PS_CREATE_STATE;

typedef struct _PS_CREATE_INFO
{
	SIZE_T Size;
	PS_CREATE_STATE State;
	union
	{
		// PsCreateInitialState
		struct
		{
			union
			{
				ULONG InitFlags;
				struct
				{
					UCHAR WriteOutputOnExit : 1;
					UCHAR DetectManifest : 1;
					UCHAR IFEOSkipDebugger : 1;
					UCHAR IFEODoNotPropagateKeyState : 1;
					UCHAR SpareBits1 : 4;
					UCHAR SpareBits2 : 8;
					USHORT ProhibitedImageCharacteristics : 16;
				} s1;
			} u1;
			ACCESS_MASK AdditionalFileAccess;
		} InitState;

		// PsCreateFailOnSectionCreate
		struct
		{
			HANDLE FileHandle;
		} FailSection;

		// PsCreateFailExeFormat
		struct
		{
			USHORT DllCharacteristics;
		} ExeFormat;

		// PsCreateFailExeName
		struct
		{
			HANDLE IFEOKey;
		} ExeName;

		// PsCreateSuccess
		struct
		{
			union
			{
				ULONG OutputFlags;
				struct
				{
					UCHAR ProtectedProcess : 1;
					UCHAR AddressSpaceOverride : 1;
					UCHAR DevOverrideEnabled : 1; // From Image File Execution Options
					UCHAR ManifestDetected : 1;
					UCHAR ProtectedProcessLight : 1;
					UCHAR SpareBits1 : 3;
					UCHAR SpareBits2 : 8;
					USHORT SpareBits3 : 16;
				} s2;
			} u2;
			HANDLE FileHandle;
			HANDLE SectionHandle;
			ULONGLONG UserProcessParametersNative;
			ULONG UserProcessParametersWow64;
			ULONG CurrentParameterFlags;
			ULONGLONG PebAddressNative;
			ULONG PebAddressWow64;
			ULONGLONG ManifestAddress;
			ULONG ManifestSize;
		} SuccessState;
	};
} PS_CREATE_INFO, *PPS_CREATE_INFO;

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED		0x00000001
#define THREAD_CREATE_FLAGS_SUPPRESS_DLLMAINS		0x00000002
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER		0x00000004
#define THREAD_CREATE_FLAGS_HAS_SECURITY_DESCRIPTOR	0x00000010 // ?
#define THREAD_CREATE_FLAGS_ACCESS_CHECK_IN_TARGET	0x00000020 // ?
#define THREAD_CREATE_FLAGS_INITIAL_THREAD			0x00000080

#define PROCESS_CREATE_FLAGS_BREAKAWAY				0x00000001
#define PROCESS_CREATE_FLAGS_NO_DEBUG_INHERIT		0x00000002
#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES		0x00000004
#define PROCESS_CREATE_FLAGS_OVERRIDE_ADDRESS_SPACE 0x00000008
#define PROCESS_CREATE_FLAGS_LARGE_PAGES			0x00000010

// Only usable with NtCreateUserProcess (Vista+):
#define PROCESS_CREATE_FLAGS_LARGE_PAGE_SYSTEM_DLL	0x00000020
#define PROCESS_CREATE_FLAGS_PROTECTED_PROCESS		0x00000040 // Only allowed if the calling process is itself protected
#define PROCESS_CREATE_FLAGS_CREATE_SESSION			0x00000080
#define PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT	0x00000100

// This is an internal type, but it hasn't changed in some 20 years or so
#define DEBUG_OBJECT_DELETE_PENDING			0x1
#define DEBUG_OBJECT_KILL_ON_CLOSE			0x2

typedef struct _DEBUG_OBJECT
{
	// Event that's set when EventList is populated.
	KEVENT EventsPresent;

	// Mutex to protect the structure
	FAST_MUTEX Mutex;

	// Queue of events waiting for debugger intervention
	LIST_ENTRY EventList;

	// Flags for the object
	ULONG Flags;
} DEBUG_OBJECT, *PDEBUG_OBJECT;

#define DEBUG_READ_EVENT					0x0001
#define DEBUG_PROCESS_ASSIGN				0x0002
#define DEBUG_SET_INFORMATION				0x0004
#define DEBUG_QUERY_INFORMATION				0x0008
#define DEBUG_ALL_ACCESS					(STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
											DEBUG_READ_EVENT | DEBUG_PROCESS_ASSIGN | DEBUG_SET_INFORMATION | \
											DEBUG_QUERY_INFORMATION)

#define ObjectNameInformation				1
#define ObjectTypesInformation				3
#define ObjectHandleFlagInformation			4
#define ObjectSessionInformation			5

typedef struct _OBJECT_BASIC_INFORMATION
{
	ULONG Attributes;
	ACCESS_MASK GrantedAccess;
	ULONG HandleCount;
	ULONG PointerCount;
	ULONG PagedPoolCharge;
	ULONG NonPagedPoolCharge;
	ULONG Reserved[3];
	ULONG NameInfoSize;
	ULONG TypeInfoSize;
	ULONG SecurityDescriptorSize;
	LARGE_INTEGER CreationTime;
} OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION;

typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING TypeName;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	UCHAR TypeIndex; // since WINBLUE
	CHAR ReservedByte;
	ULONG PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_TYPES_INFORMATION
{
	ULONG NumberOfTypes;
} OBJECT_TYPES_INFORMATION, *POBJECT_TYPES_INFORMATION;

typedef struct _OBJECT_HANDLE_FLAG_INFORMATION
{
	BOOLEAN Inherit;
	BOOLEAN ProtectFromClose;
} OBJECT_HANDLE_FLAG_INFORMATION, *POBJECT_HANDLE_FLAG_INFORMATION;

typedef struct _SE_AUDIT_PROCESS_CREATION_INFO
{
	OBJECT_NAME_INFORMATION *ImageFileName;
} SE_AUDIT_PROCESS_CREATION_INFO, *PSE_AUDIT_PROCESS_CREATION_INFO;

#define PAGE_NOACCESS					0x01
#define PAGE_READONLY					0x02
#define PAGE_READWRITE					0x04
#define PAGE_WRITECOPY					0x08
#define PAGE_EXECUTE					0x10
#define PAGE_EXECUTE_READ				0x20
#define PAGE_EXECUTE_READWRITE			0x40
#define PAGE_EXECUTE_WRITECOPY			0x80
#define PAGE_GUARD						0x100
#define PAGE_NOCACHE					0x200
#define PAGE_WRITECOMBINE				0x400

//
// PAGE_REVERT_TO_FILE_MAP can be combined with other protection
// values to specify to VirtualProtect that the argument range
// should be reverted to point back to the backing file. This
// means the contents of any private (copy on write) pages in the
// range will be discarded. Any reverted pages that were locked
// into the working set are unlocked as well.
//

#define PAGE_ENCLAVE_THREAD_CONTROL		0x80000000
#define PAGE_REVERT_TO_FILE_MAP			0x80000000
#define PAGE_TARGETS_NO_UPDATE			0x40000000
#define PAGE_TARGETS_INVALID			0x40000000
#define PAGE_ENCLAVE_UNVALIDATED		0x20000000
#define PAGE_ENCLAVE_NO_CHANGE			0x20000000
#define PAGE_ENCLAVE_DECOMMIT			0x10000000

#define MEM_COMMIT						0x00001000
#define MEM_RESERVE						0x00002000
#define MEM_DECOMMIT					0x00004000
#define MEM_RELEASE						0x00008000
#define MEM_FREE						0x00010000
#define MEM_PRIVATE						0x00020000
#define MEM_MAPPED						0x00040000
#define MEM_RESET						0x00080000
#define MEM_TOP_DOWN					0x00100000
#define MEM_WRITE_WATCH					0x00200000
#define MEM_PHYSICAL					0x00400000
#define MEM_ROTATE						0x00800000
#define MEM_DIFFERENT_IMAGE_BASE_OK		0x00800000
#define MEM_RESET_UNDO					0x01000000
#define MEM_LARGE_PAGES					0x20000000
#define MEM_4MB_PAGES					0x80000000
#define MEM_64K_PAGES 					(MEM_LARGE_PAGES | MEM_PHYSICAL)
#define SEC_64K_PAGES					0x00080000
#define SEC_FILE						0x00800000
#define SEC_IMAGE						0x01000000
#define SEC_PROTECTED_IMAGE				0x02000000
#define SEC_RESERVE						0x04000000
#define SEC_COMMIT						0x08000000
#define SEC_NOCACHE						0x10000000
#define SEC_WRITECOMBINE				0x40000000
#define SEC_LARGE_PAGES					0x80000000
#define SEC_IMAGE_NO_EXECUTE			(SEC_IMAGE | SEC_NOCACHE)
#define MEM_IMAGE 						SEC_IMAGE
#define WRITE_WATCH_FLAG_RESET			0x01
#define MEM_UNMAP_WITH_TRANSIENT_BOOST	0x01

typedef struct _RTL_USER_PROCESS_PARAMETERS *PRTL_USER_PROCESS_PARAMETERS;
typedef struct _RTL_CRITICAL_SECTION *PRTL_CRITICAL_SECTION;

#define GDI_HANDLE_BUFFER_SIZE32 34
#define GDI_HANDLE_BUFFER_SIZE64 60
#ifndef WIN64
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE32
#else
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE64
#endif
typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];
typedef ULONG GDI_HANDLE_BUFFER32[GDI_HANDLE_BUFFER_SIZE32];
typedef ULONG GDI_HANDLE_BUFFER64[GDI_HANDLE_BUFFER_SIZE64];

#define FLS_MAXIMUM_AVAILABLE 128
#define TLS_MINIMUM_AVAILABLE 64
#define TLS_EXPANSION_SLOTS 1024

#define LDR_DATA_TABLE_ENTRY_SIZE_WINXP FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, DdagNode)
#define LDR_DATA_TABLE_ENTRY_SIZE_WIN7 FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, BaseNameHashValue)
#define LDR_DATA_TABLE_ENTRY_SIZE_WIN8 FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, ImplicitPathOptions)

typedef struct _PEB
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN IsPackagedProcess : 1;
			BOOLEAN IsAppContainer : 1;
			BOOLEAN IsProtectedProcessLight : 1;
			BOOLEAN IsLongPathAwareProcess : 1;
		};
	};

	HANDLE Mutant;

	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PRTL_CRITICAL_SECTION FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	union
	{
		ULONG CrossProcessFlags;
		struct
		{
			ULONG ProcessInJob : 1;
			ULONG ProcessInitializing : 1;
			ULONG ProcessUsingVEH : 1;
			ULONG ProcessUsingVCH : 1;
			ULONG ProcessUsingFTH : 1;
			ULONG ReservedBits0 : 27;
		};
	};
	union
	{
		PVOID KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	};
	ULONG SystemReserved[1];
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID HotpatchInformation;
	PVOID *ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;

	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;

	LARGE_INTEGER CriticalSectionTimeout;
	SIZE_T HeapSegmentReserve;
	SIZE_T HeapSegmentCommit;
	SIZE_T HeapDeCommitTotalFreeThreshold;
	SIZE_T HeapDeCommitFreeBlockThreshold;

	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID *ProcessHeaps;

	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	ULONG GdiDCAttributeList;

	PRTL_CRITICAL_SECTION LoaderLock;

	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	USHORT OSBuildNumber;
	USHORT OSCSDVersion;
	ULONG OSPlatformId;
	ULONG ImageSubsystem;
	ULONG ImageSubsystemMajorVersion;
	ULONG ImageSubsystemMinorVersion;
	ULONG_PTR ActiveProcessAffinityMask;
	GDI_HANDLE_BUFFER GdiHandleBuffer;
	PVOID PostProcessInitRoutine;

	PVOID TlsExpansionBitmap;
	ULONG TlsExpansionBitmapBits[32];

	ULONG SessionId;

	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	PVOID pShimData;
	PVOID AppCompatInfo;

	UNICODE_STRING CSDVersion;

	PVOID ActivationContextData;
	PVOID ProcessAssemblyStorageMap;
	PVOID SystemDefaultActivationContextData;
	PVOID SystemAssemblyStorageMap;

	SIZE_T MinimumStackCommit;

	PVOID *FlsCallback;
	LIST_ENTRY FlsListHead;
	PVOID FlsBitmap;
	ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
	ULONG FlsHighIndex;

	PVOID WerRegistrationData;
	PVOID WerShipAssertPtr;
	PVOID pContextData;
	PVOID pImageHeaderHash;
	union
	{
		ULONG TracingFlags;
		struct
		{
			ULONG HeapTracingEnabled : 1;
			ULONG CritSecTracingEnabled : 1;
			ULONG LibLoaderTracingEnabled : 1;
			ULONG SpareTracingBits : 29;
		};
	};
	ULONGLONG CsrServerReadOnlySharedMemoryBase;
	PVOID TppWorkerpListLock;
	LIST_ENTRY TppWorkerpList;
	PVOID WaitOnAddressHashTable[128];
} PEB, *PPEB;

#define GDI_BATCH_BUFFER_SIZE 310

typedef struct _GDI_TEB_BATCH
{
	ULONG Offset;
	ULONG_PTR HDC;
	ULONG Buffer[GDI_BATCH_BUFFER_SIZE];
} GDI_TEB_BATCH, *PGDI_TEB_BATCH;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT
{
	ULONG Flags;
	PSTR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, *PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME
{
	ULONG Flags;
	struct _TEB_ACTIVE_FRAME *Previous;
	PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, *PTEB_ACTIVE_FRAME;

typedef struct _TEB
{
	NT_TIB NtTib;

	PVOID EnvironmentPointer;
	CLIENT_ID ClientId;
	PVOID ActiveRpcHandle;
	PVOID ThreadLocalStoragePointer;
	PPEB ProcessEnvironmentBlock;

	ULONG LastErrorValue;
	ULONG CountOfOwnedCriticalSections;
	PVOID CsrClientThread;
	PVOID Win32ThreadInfo;
	ULONG User32Reserved[26];
	ULONG UserReserved[5];
	PVOID WOW32Reserved;
	LCID CurrentLocale;
	ULONG FpSoftwareStatusRegister;
	PVOID ReservedForDebuggerInstrumentation[16];
	PVOID SystemReserved1[37];
	UCHAR WorkingOnBehalfTicket[8];
	NTSTATUS ExceptionCode;

	PVOID ActivationContextStackPointer;
	ULONG_PTR InstrumentationCallbackSp;
	ULONG_PTR InstrumentationCallbackPreviousPc;
	ULONG_PTR InstrumentationCallbackPreviousSp;
	ULONG TxFsContext;

	BOOLEAN InstrumentationCallbackDisabled;
	GDI_TEB_BATCH GdiTebBatch;
	CLIENT_ID RealClientId;
	HANDLE GdiCachedProcessHandle;
	ULONG GdiClientPID;
	ULONG GdiClientTID;
	PVOID GdiThreadLocalInfo;
	ULONG_PTR Win32ClientInfo[62];
	PVOID glDispatchTable[233];
	ULONG_PTR glReserved1[29];
	PVOID glReserved2;
	PVOID glSectionInfo;
	PVOID glSection;
	PVOID glTable;
	PVOID glCurrentRC;
	PVOID glContext;

	NTSTATUS LastStatusValue;
	UNICODE_STRING StaticUnicodeString;
	WCHAR StaticUnicodeBuffer[261];

	PVOID DeallocationStack;
	PVOID TlsSlots[64];
	LIST_ENTRY TlsLinks;

	PVOID Vdm;
	PVOID ReservedForNtRpc;
	PVOID DbgSsReserved[2];

	ULONG HardErrorMode;
#ifdef _WIN64
	PVOID Instrumentation[11];
#else
	PVOID Instrumentation[9];
#endif
	GUID ActivityId;

	PVOID SubProcessTag;
	PVOID PerflibData;
	PVOID EtwTraceData;
	PVOID WinSockData;
	ULONG GdiBatchCount;

	union
	{
		PROCESSOR_NUMBER CurrentIdealProcessor;
		ULONG IdealProcessorValue;
		struct
		{
			UCHAR ReservedPad0;
			UCHAR ReservedPad1;
			UCHAR ReservedPad2;
			UCHAR IdealProcessor;
		};
	};

	ULONG GuaranteedStackBytes;
	PVOID ReservedForPerf;
	PVOID ReservedForOle;
	ULONG WaitingOnLoaderLock;
	PVOID SavedPriorityState;
	ULONG_PTR ReservedForCodeCoverage;
	PVOID ThreadPoolData;
	PVOID *TlsExpansionSlots;
#ifdef _WIN64
	PVOID DeallocationBStore;
	PVOID BStoreLimit;
#endif
	ULONG MuiGeneration;
	ULONG IsImpersonating;
	PVOID NlsCache;
	PVOID pShimData;
	USHORT HeapVirtualAffinity;
	USHORT LowFragHeapDataSlot;
	HANDLE CurrentTransactionHandle;
	PTEB_ACTIVE_FRAME ActiveFrame;
	PVOID FlsData;

	PVOID PreferredLanguages;
	PVOID UserPrefLanguages;
	PVOID MergedPrefLanguages;
	ULONG MuiImpersonation;

	union
	{
		USHORT CrossTebFlags;
		USHORT SpareCrossTebBits : 16;
	};
	union
	{
		USHORT SameTebFlags;
		struct
		{
			USHORT SafeThunkCall : 1;
			USHORT InDebugPrint : 1;
			USHORT HasFiberData : 1;
			USHORT SkipThreadAttach : 1;
			USHORT WerInShipAssertCode : 1;
			USHORT RanProcessInit : 1;
			USHORT ClonedThread : 1;
			USHORT SuppressDebugMsg : 1;
			USHORT DisableUserStackWalk : 1;
			USHORT RtlExceptionAttached : 1;
			USHORT InitialThread : 1;
			USHORT SessionAware : 1;
			USHORT LoadOwner : 1;
			USHORT LoaderWorker : 1;
			USHORT SpareSameTebBits : 2;
		};
	};

	PVOID TxnScopeEnterCallback;
	PVOID TxnScopeExitCallback;
	PVOID TxnScopeContext;
	ULONG LockCount;
	LONG WowTebOffset;
	PVOID ResourceRetValue;
	PVOID ReservedForWdf;
	ULONGLONG ReservedForCrt;
	GUID EffectiveContainerId;
} TEB, *PTEB;

typedef enum _APPHELPCACHESERVICECLASS
{
	ApphelpCacheLookupEntry,
	ApphelpCacheRemoveEntry,
	ApphelpCacheInsertEntry,
	ApphelpCacheFlush,
	ApphelpCacheMax
} APPHELPCACHESERVICECLASS;

typedef struct _AHCACHE_SERVICE_DATA {
	UNICODE_STRING FileName;
	PVOID FileHandle;
} AHCACHE_SERVICE_DATA, *PAHCACHE_SERVICE_DATA;

typedef enum _MEMORY_RESERVE_TYPE
{
	MemoryReserveUserApc,
	MemoryReserveIoCompletion,
	MemoryReserveTypeMax
} MEMORY_RESERVE_TYPE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE
{
	ULONG64 Version;
	UNICODE_STRING Name;
} TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE, *PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE
{
	PVOID pValue;
	ULONG ValueLength;
} TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE, *PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_V1
{
	UNICODE_STRING Name;
	USHORT ValueType;
	USHORT Reserved;
	ULONG Flags;
	ULONG ValueCount;
	union
	{
		PLONG64 pInt64;
		PULONG64 pUint64;
		PUNICODE_STRING pString;
		PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE pFqbn;
		PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE pOctetString;
	} Values;
} TOKEN_SECURITY_ATTRIBUTE_V1, *PTOKEN_SECURITY_ATTRIBUTE_V1;

typedef struct _TOKEN_SECURITY_ATTRIBUTES_INFORMATION
{
	USHORT Version;
	USHORT Reserved;
	ULONG AttributeCount;
	union
	{
		PTOKEN_SECURITY_ATTRIBUTE_V1 pAttributeV1;
	} Attribute;
} TOKEN_SECURITY_ATTRIBUTES_INFORMATION, *PTOKEN_SECURITY_ATTRIBUTES_INFORMATION;

typedef struct _FILE_PATH
{
	ULONG Version;
	ULONG Length;
	ULONG Type;
	UCHAR FilePath[1];
} FILE_PATH, *PFILE_PATH;

typedef const WNF_STATE_NAME *PCWNF_STATE_NAME;

typedef enum _WNF_STATE_NAME_LIFETIME
{
	WnfWellKnownStateName,
	WnfPermanentStateName,
	WnfPersistentStateName,
	WnfTemporaryStateName
} WNF_STATE_NAME_LIFETIME;

typedef enum _WNF_STATE_NAME_INFORMATION
{
	WnfInfoStateNameExist,
	WnfInfoSubscribersPresent,
	WnfInfoIsQuiescent
} WNF_STATE_NAME_INFORMATION;

typedef enum _WNF_DATA_SCOPE
{
	WnfDataScopeSystem,
	WnfDataScopeSession,
	WnfDataScopeUser,
	WnfDataScopeProcess
} WNF_DATA_SCOPE;

typedef struct _WNF_TYPE_ID
{
	GUID TypeId;
} WNF_TYPE_ID, *PWNF_TYPE_ID;

typedef const WNF_TYPE_ID *PCWNF_TYPE_ID;

typedef enum _FILTER_BOOT_OPTION_OPERATION
{
	FilterBootOptionOperationOpenSystemStore,
	FilterBootOptionOperationSetElement,
	FilterBootOptionOperationDeleteElement,
	FilterBootOptionOperationMax
} FILTER_BOOT_OPTION_OPERATION;

typedef UCHAR SE_SIGNING_LEVEL, *PSE_SIGNING_LEVEL;

typedef enum _VdmServiceClass {
	VdmStartExecution,
	VdmQueueInterrupt,
	VdmDelayInterrupt,
	VdmInitialize,
	VdmFeatures,
	VdmSetInt21Handler,
	VdmQueryDir,
	VdmPrinterDirectIoOpen,
	VdmPrinterDirectIoClose,
	VdmPrinterInitialize,
	VdmSetLdtEntries,
	VdmSetProcessLdtInfo,
	VdmAdlibEmulation,
	VdmPMCliControl,
	VdmQueryVdmProcess
} VDMSERVICECLASS, *PVDMSERVICECLASS;

typedef enum _DEBUGOBJECTINFOCLASS {
	DebugObjectFlags = 1,
	MaxDebugObjectInfoClass
} DEBUGOBJECTINFOCLASS, *PDEBUGOBJECTINFOCLASS;

typedef enum _IO_COMPLETION_INFORMATION_CLASS
{
	IoCompletionBasicInformation
} IO_COMPLETION_INFORMATION_CLASS;

#define JOB_OBJECT_CPU_RATE_CONTROL_ENABLE 0x1
#define JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED 0x2
#define JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP 0x4
#define JOB_OBJECT_CPU_RATE_CONTROL_NOTIFY 0x8
#define JOB_OBJECT_CPU_RATE_CONTROL_MIN_MAX_RATE 0x10
#define JOB_OBJECT_CPU_RATE_CONTROL_VALID_FLAGS 0x1f

typedef enum _JOBOBJECTINFOCLASS
{
	JobObjectBasicAccountingInformation = 1,
	JobObjectBasicLimitInformation,
	JobObjectBasicProcessIdList,
	JobObjectBasicUIRestrictions,
	JobObjectSecurityLimitInformation,  // deprecated
	JobObjectEndOfJobTimeInformation,
	JobObjectAssociateCompletionPortInformation,
	JobObjectBasicAndIoAccountingInformation,
	JobObjectExtendedLimitInformation,
	JobObjectJobSetInformation,
	JobObjectGroupInformation,
	JobObjectNotificationLimitInformation,
	JobObjectLimitViolationInformation,
	JobObjectGroupInformationEx,
	JobObjectCpuRateControlInformation,
	JobObjectCompletionFilter,
	JobObjectCompletionCounter,
	JobObjectReserved1Information = 18,
	JobObjectReserved2Information,
	JobObjectReserved3Information,
	JobObjectReserved4Information,
	JobObjectReserved5Information,
	JobObjectReserved6Information,
	JobObjectReserved7Information,
	JobObjectReserved8Information,
	JobObjectReserved9Information,
	JobObjectReserved10Information,
	JobObjectReserved11Information,
	JobObjectReserved12Information,
	JobObjectReserved13Information,
	JobObjectReserved14Information = 31,
	JobObjectNetRateControlInformation,
	JobObjectNotificationLimitInformation2,
	JobObjectLimitViolationInformation2,
	JobObjectCreateSilo,
	JobObjectSiloBasicInformation,
	JobObjectReserved15Information = 37,
	JobObjectReserved16Information = 38,
	JobObjectReserved17Information = 39,
	JobObjectReserved18Information = 40,
	JobObjectReserved19Information = 41,
	JobObjectReserved20Information = 42,
	JobObjectReserved21Information = 43,
	JobObjectReserved22Information = 44,
	JobObjectReserved23Information = 45,
	JobObjectReserved24Information = 46,
	JobObjectReserved25Information = 47,
	MaxJobObjectInfoClass
} JOBOBJECTINFOCLASS;

typedef enum _SECTION_INFORMATION_CLASS
{
	SectionBasicInformation,
	SectionImageInformation,
	SectionRelocationInformation, // name:wow64:whNtQuerySection_SectionRelocationInformation
	SectionOriginalBaseInformation, // PVOID BaseAddress
	MaxSectionInfoClass
} SECTION_INFORMATION_CLASS;

typedef enum _SYSDBG_COMMAND
{
	SysDbgQueryModuleInformation,
	SysDbgQueryTraceInformation,
	SysDbgSetTracepoint,
	SysDbgSetSpecialCall,
	SysDbgClearSpecialCalls,
	SysDbgQuerySpecialCalls,
	SysDbgBreakPoint,
	SysDbgQueryVersion,
	SysDbgReadVirtual,
	SysDbgWriteVirtual,
	SysDbgReadPhysical,
	SysDbgWritePhysical,
	SysDbgReadControlSpace,
	SysDbgWriteControlSpace,
	SysDbgReadIoSpace,
	SysDbgWriteIoSpace,
	SysDbgReadMsr,
	SysDbgWriteMsr,
	SysDbgReadBusData,
	SysDbgWriteBusData,
	SysDbgCheckLowMemory,
	SysDbgEnableKernelDebugger,
	SysDbgDisableKernelDebugger,
	SysDbgGetAutoKdEnable,
	SysDbgSetAutoKdEnable,
	SysDbgGetPrintBufferSize,
	SysDbgSetPrintBufferSize,
	SysDbgGetKdUmExceptionEnable,
	SysDbgSetKdUmExceptionEnable,
	SysDbgGetTriageDump,
	SysDbgGetKdBlockEnable,
	SysDbgSetKdBlockEnable,
	SysDbgRegisterForUmBreakInfo,
	SysDbgGetUmBreakPid,
	SysDbgClearUmBreakPid,
	SysDbgGetUmAttachPid,
	SysDbgClearUmAttachPid,
	SysDbgGetLiveKernelDump
} SYSDBG_COMMAND, *PSYSDBG_COMMAND;

typedef enum _ATOM_INFORMATION_CLASS
{
	AtomBasicInformation,
	AtomTableInformation
} ATOM_INFORMATION_CLASS;

typedef enum _SHUTDOWN_ACTION
{
	ShutdownNoReboot,
	ShutdownReboot,
	ShutdownPowerOff
} SHUTDOWN_ACTION;

typedef VOID (*PPS_APC_ROUTINE)(
	_In_opt_ PVOID ApcArgument1,
	_In_opt_ PVOID ApcArgument2,
	_In_opt_ PVOID ApcArgument3
	);

typedef struct _INITIAL_TEB
{
	struct
	{
		PVOID OldStackBase;
		PVOID OldStackLimit;
	} OldInitialTeb;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID StackAllocationBase;
} INITIAL_TEB, *PINITIAL_TEB;

typedef USHORT RTL_ATOM, *PRTL_ATOM;

// The syscall declarations below were autogenerated from the entire list of syscalls, and then culled to remove WDM/ntddk collisions. So:
// (1) Some declarations are missing
// (2) Not all of the Zw* declarations are actually exported by the kernel. If you use one, hit compile first to check for linker errors
// The Nt* declarations on the other hand *are* all exported, and *only* as Nt, not Zw.
// Update: I've made an exception to this for some syscalls that can be imported as either: static Nt* imports have a slight advantage if
// you know for certain that PreviousMode will be Kernel (e.g. in DriverEntry context), as they can't be hooked as easily through e.g. the SSDT.
// Imports that exist in both Nt* and Zw* versions will be in the regular list further below, with Nt appearing first followed by Zw.

NTSYSCALLAPI
NTSTATUS
NTAPI
NtAddAtom(
	_In_ PWSTR AtomName,
	_In_ ULONG Length,
	_Out_opt_ PRTL_ATOM Atom
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtAllocateUuids(
	_Out_ PULARGE_INTEGER Time,
	_Out_ PULONG Range,
	_Out_ PULONG Sequence,
	_Out_ PCHAR Seed
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtDeleteAtom(
	_In_ RTL_ATOM Atom
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtFindAtom(
	_In_ PWSTR AtomName,
	_In_ ULONG Length,
	_Out_opt_ PRTL_ATOM Atom
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtFreezeTransactions(
	_In_ PLARGE_INTEGER FreezeTimeout,
	_In_ PLARGE_INTEGER ThawTimeout
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtMakePermanentObject(
	_In_ HANDLE Handle
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtNotifyChangeDirectoryFile(
	_In_ HANDLE FileHandle,
	_In_opt_ HANDLE Event,
	_In_opt_ PIO_APC_ROUTINE ApcRoutine,
	_In_opt_ PVOID ApcContext,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_Out_ FILE_NOTIFY_INFORMATION Buffer,
	_In_ ULONG Length,
	_In_ ULONG CompletionFilter,
	_In_ BOOLEAN WatchTree
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryInformationAtom(
	_In_ RTL_ATOM Atom,
	_In_ ATOM_INFORMATION_CLASS AtomInformationClass,
	_Out_ PVOID AtomInformation,
	_In_ ULONG AtomInformationLength,
	_Out_opt_ PULONG ReturnLength
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQuerySystemInformationEx(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_In_ PVOID InputBuffer,
	_In_ ULONG InputBufferLength,
	_Out_opt_ PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
	);

// Added even though it is available as Zw*, because ThreadInformationClass = ThreadWow64Context gives very
// different results depending on previous mode. (Also goes for NtSetInformationThread but that is in ntifs.h.)
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryInformationThread(
	_In_ HANDLE ThreadHandle,
	_In_ THREADINFOCLASS ThreadInformationClass,
	_Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
	_In_ ULONG ThreadInformationLength,
	_Out_opt_ PULONG ReturnLength
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtShutdownSystem(
	_In_ SHUTDOWN_ACTION Action
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtThawTransactions(
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtTraceControl(
	_In_ ULONG FunctionCode,
	_In_ PVOID InBuffer,
	_In_ ULONG InBufferLen,
	_Out_opt_ PVOID OutBuffer,
	_In_ ULONG OutBufferLen,
	_Out_ PULONG ReturnLength
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtVdmControl(
	_In_ VDMSERVICECLASS Service,
	_Inout_ PVOID ServiceData
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwAccessCheck(
	_In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
	_In_ HANDLE ClientToken,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ PGENERIC_MAPPING GenericMapping,
	_Out_ PPRIVILEGE_SET PrivilegeSet,
	_Inout_ PULONG PrivilegeSetLength,
	_Out_ PACCESS_MASK GrantedAccess,
	_Out_ PNTSTATUS AccessStatus
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwAccessCheckAndAuditAlarm(
	_In_ PUNICODE_STRING SubsystemName,
	_In_opt_ PVOID HandleId,
	_In_ PUNICODE_STRING ObjectTypeName,
	_In_ PUNICODE_STRING ObjectName,
	_In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ PGENERIC_MAPPING GenericMapping,
	_In_ BOOLEAN ObjectCreation,
	_Out_ PACCESS_MASK GrantedAccess,
	_Out_ PNTSTATUS AccessStatus,
	_Out_ PBOOLEAN GenerateOnClose
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwAcquireCMFViewOwnership(
	_Out_ PULONGLONG TimeStamp,
	_Out_ PBOOLEAN tokenTaken,
	_In_ BOOLEAN replaceExisting
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwAdjustPrivilegesToken(
	_In_ HANDLE TokenHandle,
	_In_ BOOLEAN DisableAllPrivileges,
	_In_opt_ PTOKEN_PRIVILEGES NewState,
	_In_ ULONG BufferLength,
	_Out_writes_bytes_to_opt_(BufferLength, *ReturnLength) PTOKEN_PRIVILEGES PreviousState,
	_Out_ _When_(PreviousState == NULL, _Out_opt_) PULONG ReturnLength
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwAlertResumeThread(
	_In_ HANDLE ThreadHandle,
	_Out_opt_ PULONG PreviousSuspendCount
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwAlertThread(
	_In_ HANDLE ThreadHandle
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwAlertThreadByThreadId(
	_In_ HANDLE ThreadId
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwAllocateReserveObject(
	_Out_ PHANDLE MemoryReserveHandle,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ MEMORY_RESERVE_TYPE Type
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwAllocateUserPhysicalPages(
	_In_ HANDLE ProcessHandle,
	_Inout_ PULONG_PTR NumberOfPages,
	_Out_ PULONG_PTR UserPfnArray
	);

#if (NTDDI_VERSION >= NTDDI_WIN10_RS5)
_Must_inspect_result_
_IRQL_requires_max_(PASSIVE_LEVEL)
_When_(return == 0, __drv_allocatesMem(Region))
NTSYSAPI
NTSTATUS
NTAPI
ZwAllocateVirtualMemoryEx(
	_In_ HANDLE ProcessHandle,
	_Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID* BaseAddress,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG AllocationType,
	_In_ ULONG PageProtection,
	_Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
	_In_ ULONG ExtendedParameterCount
	);
#endif

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwApphelpCacheControl(
	_In_ APPHELPCACHESERVICECLASS Service,
	_In_ PAHCACHE_SERVICE_DATA ServiceData
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwAreMappedFilesTheSame(
	_In_ PVOID File1MappedAsAnImage,
	_In_ PVOID File2MappedAsFile
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwAssignProcessToJobObject(
	_In_ HANDLE JobHandle,
	_In_ HANDLE ProcessHandle
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwAssociateWaitCompletionPacket(
	_In_ HANDLE WaitCompletionPacketHandle,
	_In_ HANDLE IoCompletionHandle,
	_In_ HANDLE TargetObjectHandle,
	_In_opt_ PVOID KeyContext,
	_In_opt_ PVOID ApcContext,
	_In_ NTSTATUS IoStatus,
	_In_ ULONG_PTR IoStatusInformation,
	_Out_opt_ PBOOLEAN AlreadySignaled
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCallbackReturn(
	_In_ PVOID OutputBuffer,
	_In_ ULONG OutputLength,
	_In_ NTSTATUS Status
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCancelDeviceWakeupRequest(
	_In_ HANDLE Device
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCancelIoFile(
	_In_ HANDLE FileHandle,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCancelIoFileEx(
	_In_ HANDLE FileHandle,
	_In_opt_ PIO_STATUS_BLOCK IoRequestToCancel,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCancelSynchronousIoFile(
	_In_ HANDLE ThreadHandle,
	_In_opt_ PIO_STATUS_BLOCK IoRequestToCancel,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCancelWaitCompletionPacket(
	_In_ HANDLE WaitCompletionPacketHandle,
	_In_ BOOLEAN RemoveSignaledPacket
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwClearEvent(
	_In_ HANDLE EventHandle
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCloseObjectAuditAlarm(
	_In_ PUNICODE_STRING SubsystemName,
	_In_opt_ PVOID HandleId,
	_In_ BOOLEAN GenerateOnClose
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCompactKeys(
	_In_ ULONG Count,
	_In_ HANDLE KeyArray[]
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCompareObjects(
	_In_ HANDLE FirstObjectHandle,
	_In_ HANDLE SecondObjectHandle
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCompareTokens(
	_In_ HANDLE FirstTokenHandle,
	_In_ HANDLE SecondTokenHandle,
	_Out_ PBOOLEAN Equal
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCompressKey(
	_In_ HANDLE Key
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwContinue(
	_In_ PCONTEXT ContextRecord,
	_In_ BOOLEAN TestAlert
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCreateDebugObject(
	_Out_ PHANDLE DebugObjectHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ ULONG Flags
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCreateDirectoryObjectEx(
	_Out_ PHANDLE DirectoryHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ HANDLE ShadowDirectoryHandle,
	_In_ ULONG Flags
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCreateEventPair(
	_Out_ PHANDLE EventPairHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCreateIRTimer(
	_Out_ PHANDLE TimerHandle,
	_In_ ACCESS_MASK DesiredAccess
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCreateIoCompletion(
	_Out_ PHANDLE IoCompletionHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ ULONG Count
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCreateJobObject(
	_Out_ PHANDLE JobHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCreateKeyedEvent(
	_Out_ PHANDLE KeyedEventHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ ULONG Flags
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCreateMailslotFile(
	_Out_ PHANDLE FileHandle,
	_In_ ULONG DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_ ULONG CreateOptions,
	_In_ ULONG MailslotQuota,
	_In_ ULONG MaximumMessageSize,
	_In_ PLARGE_INTEGER ReadTimeout
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCreateMutant(
	_Out_ PHANDLE MutantHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ BOOLEAN InitialOwner
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCreateNamedPipeFile(
	_Out_ PHANDLE FileHandle,
	_In_ ULONG DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_ ULONG ShareAccess,
	_In_ ULONG CreateDisposition,
	_In_ ULONG CreateOptions,
	_In_ ULONG NamedPipeType,
	_In_ ULONG ReadMode,
	_In_ ULONG CompletionMode,
	_In_ ULONG MaximumInstances,
	_In_ ULONG InboundQuota,
	_In_ ULONG OutboundQuota,
	_In_opt_ PLARGE_INTEGER DefaultTimeout
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCreatePagingFile(
	_In_ PUNICODE_STRING PageFileName,
	_In_ PLARGE_INTEGER MinimumSize,
	_In_ PLARGE_INTEGER MaximumSize,
	_In_ ULONG Priority
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCreatePartition(
	_Out_ PHANDLE PartitionHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ ULONG PreferredNode
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCreatePrivateNamespace(
	_Out_ PHANDLE NamespaceHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ PVOID BoundaryDescriptor
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCreateProcess(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ HANDLE ParentProcess,
	_In_ BOOLEAN InheritObjectTable,
	_In_opt_ HANDLE SectionHandle,
	_In_opt_ HANDLE DebugPort,
	_In_opt_ HANDLE ExceptionPort
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCreateProcessEx(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ HANDLE ParentProcess,
	_In_ ULONG Flags,
	_In_opt_ HANDLE SectionHandle,
	_In_opt_ HANDLE DebugPort,
	_In_opt_ HANDLE ExceptionPort,
	_In_ ULONG JobMemberLevel
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCreateProfile(
	_Out_ PHANDLE ProfileHandle,
	_In_opt_ HANDLE Process,
	_In_ PVOID ProfileBase,
	_In_ SIZE_T ProfileSize,
	_In_ ULONG BucketSize,
	_In_ PULONG Buffer,
	_In_ ULONG BufferSize,
	_In_ KPROFILE_SOURCE ProfileSource,
	_In_ KAFFINITY Affinity
	);

#if (NTDDI_VERSION >= NTDDI_WIN10_RS5)
_Must_inspect_result_
NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateSectionEx(
	_Out_ PHANDLE SectionHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PLARGE_INTEGER MaximumSize,
	_In_ ULONG SectionPageProtection,
	_In_ ULONG AllocationAttributes,
	_In_opt_ HANDLE FileHandle,
	_Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
	_In_ ULONG ExtendedParameterCount
	);
#endif

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCreateSemaphore(
	_Out_ PHANDLE SemaphoreHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ LONG InitialCount,
	_In_ LONG MaximumCount
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCreateSymbolicLinkObject(
	_Out_ PHANDLE LinkHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ PUNICODE_STRING LinkTarget
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCreateThread(
	_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ HANDLE ProcessHandle,
	_Out_ PCLIENT_ID ClientId,
	_In_ PCONTEXT ThreadContext,
	_In_ PINITIAL_TEB InitialTeb,
	_In_ BOOLEAN CreateSuspended
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCreateThreadEx(
	_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ HANDLE ProcessHandle,
	_In_ PVOID StartRoutine, // PUSER_THREAD_START_ROUTINE
	_In_opt_ PVOID Argument,
	_In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
	_In_ SIZE_T ZeroBits,
	_In_ SIZE_T StackSize,
	_In_ SIZE_T MaximumStackSize,
	_In_opt_ PPS_ATTRIBUTE_LIST AttributeList
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCreateTimer2(
	_Out_ PHANDLE TimerHandle,
	_In_opt_ PVOID Reserved1,
	_In_opt_ PVOID Reserved2,
	_In_ ULONG Attributes,
	_In_ ACCESS_MASK DesiredAccess
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCreateToken(
	_Out_ PHANDLE TokenHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ TOKEN_TYPE TokenType,
	_In_ PLUID AuthenticationId,
	_In_ PLARGE_INTEGER ExpirationTime,
	_In_ PTOKEN_USER User,
	_In_ PTOKEN_GROUPS Groups,
	_In_ PTOKEN_PRIVILEGES Privileges,
	_In_opt_ PTOKEN_OWNER Owner,
	_In_ PTOKEN_PRIMARY_GROUP PrimaryGroup,
	_In_opt_ PTOKEN_DEFAULT_DACL DefaultDacl,
	_In_ PTOKEN_SOURCE TokenSource
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCreateTokenEx(
	_Out_ PHANDLE TokenHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ TOKEN_TYPE TokenType,
	_In_ PLUID AuthenticationId,
	_In_ PLARGE_INTEGER ExpirationTime,
	_In_ PTOKEN_USER User,
	_In_ PTOKEN_GROUPS Groups,
	_In_ PTOKEN_PRIVILEGES Privileges,
	_In_opt_ PTOKEN_SECURITY_ATTRIBUTES_INFORMATION UserAttributes,
	_In_opt_ PTOKEN_SECURITY_ATTRIBUTES_INFORMATION DeviceAttributes,
	_In_opt_ PTOKEN_GROUPS DeviceGroups,
	_In_opt_ PTOKEN_MANDATORY_POLICY TokenMandatoryPolicy,
	_In_opt_ PTOKEN_OWNER Owner,
	_In_ PTOKEN_PRIMARY_GROUP PrimaryGroup,
	_In_opt_ PTOKEN_DEFAULT_DACL DefaultDacl,
	_In_ PTOKEN_SOURCE TokenSource
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCreateUserProcess(
	_Out_ PHANDLE ProcessHandle,
	_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK ProcessDesiredAccess,
	_In_ ACCESS_MASK ThreadDesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ProcessObjectAttributes,
	_In_opt_ POBJECT_ATTRIBUTES ThreadObjectAttributes,
	_In_ ULONG ProcessFlags, // PROCESS_CREATE_FLAGS_*
	_In_ ULONG ThreadFlags, // THREAD_CREATE_FLAGS_*
	_In_opt_ PVOID ProcessParameters, // PRTL_USER_PROCESS_PARAMETERS
	_Inout_ PPS_CREATE_INFO CreateInfo,
	_In_opt_ PPS_ATTRIBUTE_LIST AttributeList
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCreateWaitCompletionPacket(
	_Out_ PHANDLE WaitCompletionPacketHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwCreateWnfStateName(
	_Out_ PWNF_STATE_NAME StateName,
	_In_ WNF_STATE_NAME_LIFETIME NameLifetime,
	_In_ WNF_DATA_SCOPE DataScope,
	_In_ BOOLEAN PersistData,
	_In_opt_ PCWNF_TYPE_ID TypeId,
	_In_ ULONG MaximumStateSize,
	_In_ PSECURITY_DESCRIPTOR SecurityDescriptor
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwDebugActiveProcess(
	_In_ HANDLE ProcessHandle,
	_In_ HANDLE DebugObjectHandle
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwDebugContinue(
	_In_ HANDLE DebugObjectHandle,
	_In_ PCLIENT_ID ClientId,
	_In_ NTSTATUS ContinueStatus
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwDelayExecution(
	_In_ BOOLEAN Alertable,
	_In_ PLARGE_INTEGER DelayInterval
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwDeleteBootEntry(
	_In_ ULONG Id
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwDeleteDriverEntry(
	_In_ ULONG Id
	);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
NtDeleteFile( // The Zw version is in ntifs.h
	_In_ POBJECT_ATTRIBUTES ObjectAttributes
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwDeleteObjectAuditAlarm(
	_In_ PUNICODE_STRING SubsystemName,
	_In_opt_ PVOID HandleId,
	_In_ BOOLEAN GenerateOnClose
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwDeletePrivateNamespace(
	_In_ HANDLE NamespaceHandle
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwDeleteWnfStateData(
	_In_ PCWNF_STATE_NAME StateName,
	_In_opt_ const VOID *ExplicitScope
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwDeleteWnfStateName(
	_In_ PCWNF_STATE_NAME StateName
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwDisableLastKnownGood(
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwDrawText(
	_In_ PUNICODE_STRING String
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwEnableLastKnownGood(
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwEnumerateBootEntries(
	_Out_ PVOID Buffer,
	_Inout_ PULONG BufferLength
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwEnumerateDriverEntries(
	_Out_ PVOID Buffer,
	_Inout_ PULONG BufferLength
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwEnumerateSystemEnvironmentValuesEx(
	_In_ ULONG InformationClass,
	_Out_ PVOID Buffer,
	_Inout_ PULONG BufferLength
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwExtendSection(
	_In_ HANDLE SectionHandle,
	_Inout_ PLARGE_INTEGER NewSectionSize
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwFilterBootOption(
	_In_ FILTER_BOOT_OPTION_OPERATION FilterOperation,
	_In_ ULONG ObjectType,
	_In_ ULONG ElementType,
	_In_ PVOID Data,
	_In_ ULONG DataSize
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwFilterToken(
	_In_ HANDLE ExistingTokenHandle,
	_In_ ULONG Flags,
	_In_opt_ PTOKEN_GROUPS SidsToDisable,
	_In_opt_ PTOKEN_PRIVILEGES PrivilegesToDelete,
	_In_opt_ PTOKEN_GROUPS RestrictedSids,
	_Out_ PHANDLE NewTokenHandle
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwFilterTokenEx(
	_In_ HANDLE ExistingTokenHandle,
	_In_ ULONG Flags,
	_In_opt_ PTOKEN_GROUPS SidsToDisable,
	_In_opt_ PTOKEN_PRIVILEGES PrivilegesToDelete,
	_In_opt_ PTOKEN_GROUPS RestrictedSids,
	_In_ ULONG DisableUserClaimsCount,
	_In_opt_ PUNICODE_STRING UserClaimsToDisable,
	_In_ ULONG DisableDeviceClaimsCount,
	_In_opt_ PUNICODE_STRING DeviceClaimsToDisable,
	_In_opt_ PTOKEN_GROUPS DeviceGroupsToDisable,
	_In_opt_ PTOKEN_SECURITY_ATTRIBUTES_INFORMATION RestrictedUserAttributes,
	_In_opt_ PTOKEN_SECURITY_ATTRIBUTES_INFORMATION RestrictedDeviceAttributes,
	_In_opt_ PTOKEN_GROUPS RestrictedDeviceGroups,
	_Out_ PHANDLE NewTokenHandle
	);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwFlushBuffersFileEx(
	_In_ HANDLE FileHandle,
	_In_ ULONG Flags,
	_In_reads_bytes_(ParametersSize) PVOID Parameters,
	_In_ ULONG ParametersSize,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwFlushInstallUILanguage(
	_In_ LANGID InstallUILanguage,
	_In_ ULONG SetComittedFlag
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwFlushInstructionCache(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_In_ SIZE_T Length
	);

NTSYSCALLAPI
VOID
NTAPI
ZwFlushProcessWriteBuffers(
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwFlushWriteBuffer(
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwFreeUserPhysicalPages(
	_In_ HANDLE ProcessHandle,
	_Inout_ PULONG_PTR NumberOfPages,
	_In_ PULONG_PTR UserPfnArray
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwFreezeRegistry(
	_In_ ULONG TimeOutInSeconds
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwGetCachedSigningLevel(
	_In_ HANDLE File,
	_Out_ PULONG Flags,
	_Out_ PSE_SIGNING_LEVEL SigningLevel,
	_Out_ PUCHAR Thumbprint,
	_Inout_opt_ PULONG ThumbprintSize,
	_Out_opt_ PULONG ThumbprintAlgorithm
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwGetContextThread(
	_In_ HANDLE ThreadHandle,
	_Inout_ PCONTEXT ThreadContext
	);

NTSYSCALLAPI
ULONG
NTAPI
ZwGetCurrentProcessorNumber(
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwGetDevicePowerState(
	_In_ HANDLE Device,
	_Out_ PDEVICE_POWER_STATE State
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwGetEnvironmentVariableEx(
	_In_ PWSTR VariableName,
	_In_ LPGUID VendorGuid,
	_Out_ PVOID Value,
	_Inout_ PULONG ValueLength,
	_Out_opt_ PULONG Attributes
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwGetMUIRegistryInfo(
	_In_ ULONG Flags,
	_Inout_ PULONG DataSize,
	_Out_ PVOID Data
	);

#if NTDDI_VERSION >= NTDDI_WIN10
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwGetNextProcess(
	_In_ HANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ ULONG HandleAttributes,
	_In_ ULONG Flags,
	_Out_ PHANDLE NewProcessHandle
	);
#endif

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwGetNextThread(
	_In_ HANDLE ProcessHandle,
	_In_ HANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ ULONG HandleAttributes,
	_In_ ULONG Flags,
	_Out_ PHANDLE NewThreadHandle
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwGetNlsSectionPtr(
	_In_ ULONG SectionType,
	_In_ ULONG SectionData,
	_In_ PVOID ContextData,
	_Out_ PVOID *SectionPointer,
	_Out_ PULONG SectionSize
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwGetWriteWatch(
	_In_ HANDLE ProcessHandle,
	_In_ ULONG Flags,
	_In_ PVOID BaseAddress,
	_In_ SIZE_T RegionSize,
	_Out_ PVOID *UserAddressArray,
	_Inout_ PULONG_PTR EntriesInUserAddressArray,
	_Out_ PULONG Granularity
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwImpersonateAnonymousToken(
	_In_ HANDLE ThreadHandle
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwImpersonateThread(
	_In_ HANDLE ServerThreadHandle,
	_In_ HANDLE ClientThreadHandle,
	_In_ PSECURITY_QUALITY_OF_SERVICE SecurityQos
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwInitializeNlsFiles(
	_Out_ PVOID *BaseAddress,
	_Out_ PLCID DefaultLocaleId,
	_Out_ PLARGE_INTEGER DefaultCasingTableSize
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwInitializeRegistry(
	_In_ USHORT BootCondition
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwInitiatePowerAction(
	_In_ POWER_ACTION SystemAction,
	_In_ SYSTEM_POWER_STATE LightestSystemState,
	_In_ ULONG Flags, // POWER_ACTION_* flags
	_In_ BOOLEAN Asynchronous
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwIsProcessInJob(
	_In_ HANDLE ProcessHandle,
	_In_opt_ HANDLE JobHandle
	);

NTSYSCALLAPI
BOOLEAN
NTAPI
ZwIsSystemResumeAutomatic(
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwIsUILanguageComitted(
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwLoadKey(
	_In_ POBJECT_ATTRIBUTES TargetKey,
	_In_ POBJECT_ATTRIBUTES SourceFile
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwLoadKey2(
	_In_ POBJECT_ATTRIBUTES TargetKey,
	_In_ POBJECT_ATTRIBUTES SourceFile,
	_In_ ULONG Flags
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwLoadKeyEx(
	_In_ POBJECT_ATTRIBUTES TargetKey,
	_In_ POBJECT_ATTRIBUTES SourceFile,
	_In_ ULONG Flags,
	_In_opt_ HANDLE TrustClassKey,
	_In_opt_ HANDLE Event,
	_In_opt_ ACCESS_MASK DesiredAccess,
	_Out_opt_ PHANDLE RootHandle,
	_Out_opt_ PIO_STATUS_BLOCK IoStatus
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwLockProductActivationKeys(
	_Inout_opt_ ULONG *pPrivateVer,
	_Out_opt_ ULONG *pSafeMode
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwLockRegistryKey(
	_In_ HANDLE KeyHandle
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwLockVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID *BaseAddress,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG MapType
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwMapCMFModule(
	_In_ ULONG What,
	_In_ ULONG Index,
	_Out_opt_ PULONG CacheIndexOut,
	_Out_opt_ PULONG CacheFlagsOut,
	_Out_opt_ PULONG ViewSizeOut,
	_Out_opt_ PVOID *BaseAddress
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwMapUserPhysicalPages(
	_In_ PVOID VirtualAddress,
	_In_ ULONG_PTR NumberOfPages,
	_In_ PULONG_PTR UserPfnArray
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwMapUserPhysicalPagesScatter(
	_In_ PVOID *VirtualAddresses,
	_In_ ULONG_PTR NumberOfPages,
	_In_ PULONG_PTR UserPfnArray
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwNotifyChangeMultipleKeys(
	_In_ HANDLE MasterKeyHandle,
	_In_opt_ ULONG Count,
	_In_ OBJECT_ATTRIBUTES SubordinateObjects[],
	_In_opt_ HANDLE Event,
	_In_opt_ PIO_APC_ROUTINE ApcRoutine,
	_In_opt_ PVOID ApcContext,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_ ULONG CompletionFilter,
	_In_ BOOLEAN WatchTree,
	_Out_ PVOID Buffer,
	_In_ ULONG BufferSize,
	_In_ BOOLEAN Asynchronous
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwOpenEventPair(
	_Out_ PHANDLE EventPairHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwOpenIoCompletion(
	_Out_ PHANDLE IoCompletionHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwOpenJobObject(
	_Out_ PHANDLE JobHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwOpenKeyedEvent(
	_Out_ PHANDLE KeyedEventHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwOpenMutant(
	_Out_ PHANDLE MutantHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwOpenObjectAuditAlarm(
	_In_ PUNICODE_STRING SubsystemName,
	_In_opt_ PVOID HandleId,
	_In_ PUNICODE_STRING ObjectTypeName,
	_In_ PUNICODE_STRING ObjectName,
	_In_opt_ PSECURITY_DESCRIPTOR SecurityDescriptor,
	_In_ HANDLE ClientToken,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ ACCESS_MASK GrantedAccess,
	_In_opt_ PPRIVILEGE_SET Privileges,
	_In_ BOOLEAN ObjectCreation,
	_In_ BOOLEAN AccessGranted,
	_Out_ PBOOLEAN GenerateOnClose
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwOpenPartition(
	_Out_ PHANDLE PartitionHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwOpenPrivateNamespace(
	_Out_ PHANDLE NamespaceHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ PVOID BoundaryDescriptor
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwOpenProcessToken(
	_In_ HANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_Out_ PHANDLE TokenHandle
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwOpenSemaphore(
	_Out_ PHANDLE SemaphoreHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwOpenSession(
	_Out_ PHANDLE SessionHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwOpenThread(
	_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwOpenThreadToken(
	_In_ HANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ BOOLEAN OpenAsSelf,
	_Out_ PHANDLE TokenHandle
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwPrivilegeCheck(
	_In_ HANDLE ClientToken,
	_Inout_ PPRIVILEGE_SET RequiredPrivileges,
	_Out_ PBOOLEAN Result
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwPrivilegeObjectAuditAlarm(
	_In_ PUNICODE_STRING SubsystemName,
	_In_opt_ PVOID HandleId,
	_In_ HANDLE ClientToken,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ PPRIVILEGE_SET Privileges,
	_In_ BOOLEAN AccessGranted
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwPrivilegedServiceAuditAlarm(
	_In_ PUNICODE_STRING SubsystemName,
	_In_ PUNICODE_STRING ServiceName,
	_In_ HANDLE ClientToken,
	_In_ PPRIVILEGE_SET Privileges,
	_In_ BOOLEAN AccessGranted
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwPropagationComplete(
	_In_ HANDLE ResourceManagerHandle,
	_In_ ULONG RequestCookie,
	_In_ ULONG BufferLength,
	_In_ PVOID Buffer
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwPropagationFailed(
	_In_ HANDLE ResourceManagerHandle,
	_In_ ULONG RequestCookie,
	_In_ NTSTATUS PropStatus
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwPulseEvent(
	_In_ HANDLE EventHandle,
	_Out_opt_ PLONG PreviousState
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryAttributesFile(
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PFILE_BASIC_INFORMATION FileInformation
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryBootEntryOrder(
	_Out_ PULONG Ids,
	_Inout_ PULONG Count
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryDebugFilterState(
	_In_ ULONG ComponentId,
	_In_ ULONG Level
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryDefaultLocale(
	_In_ BOOLEAN UserProfile,
	_Out_ PLCID DefaultLocaleId
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryDefaultUILanguage(
	_Out_ LANGID *DefaultUILanguageId
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryDirectoryObject(
	_In_ HANDLE DirectoryHandle,
	_Out_ PVOID Buffer,
	_In_ ULONG Length,
	_In_ BOOLEAN ReturnSingleEntry,
	_In_ BOOLEAN RestartScan,
	_Inout_ PULONG Context,
	_Out_opt_ PULONG ReturnLength
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryDriverEntryOrder(
	_Out_ PULONG Ids,
	_Inout_ PULONG Count
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryInformationProcess(
	_In_ HANDLE ProcessHandle,
	_In_ PROCESSINFOCLASS ProcessInformationClass,
	_Out_ PVOID ProcessInformation,
	_In_ ULONG ProcessInformationLength,
	_Out_opt_ PULONG ReturnLength
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryInformationProcess(
	_In_ HANDLE ProcessHandle,
	_In_ PROCESSINFOCLASS ProcessInformationClass,
	_Out_ PVOID ProcessInformation,
	_In_ ULONG ProcessInformationLength,
	_Out_opt_ PULONG ReturnLength
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryInformationThread(
	_In_ HANDLE ThreadHandle,
	_In_ THREADINFOCLASS ThreadInformationClass,
	_Out_ PVOID ThreadInformation,
	_In_ ULONG ThreadInformationLength,
	_Out_opt_ PULONG ReturnLength
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryInstallUILanguage(
	_Out_ LANGID *InstallUILanguageId
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryIntervalProfile(
	_In_ KPROFILE_SOURCE ProfileSource,
	_Out_ PULONG Interval
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryIoCompletion(
	_In_ HANDLE IoCompletionHandle,
	_In_ IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass,
	_Out_ PVOID IoCompletionInformation,
	_In_ ULONG IoCompletionInformationLength,
	_Out_opt_ PULONG ReturnLength
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryLicenseValue(
	_In_ PUNICODE_STRING ValueName,
	_Out_opt_ PULONG Type,
	_Out_ PVOID Data,
	_In_ ULONG DataSize,
	_Out_ PULONG ResultDataSize
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryMultipleValueKey(
	_In_ HANDLE KeyHandle,
	_Inout_opt_ PKEY_VALUE_ENTRY ValueEntries,
	_In_ ULONG EntryCount,
	_Out_ PVOID ValueBuffer,
	_Inout_ PULONG BufferLength,
	_Out_opt_ PULONG RequiredBufferLength
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryOpenSubKeys(
	_In_ POBJECT_ATTRIBUTES TargetKey,
	_Out_ PULONG HandleCount
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryOpenSubKeysEx(
	_In_ POBJECT_ATTRIBUTES TargetKey,
	_In_ ULONG BufferLength,
	_Out_ PVOID Buffer,
	_Out_ PULONG RequiredSize
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryPerformanceCounter(
	_Out_ PLARGE_INTEGER PerformanceCounter,
	_Out_opt_ PLARGE_INTEGER PerformanceFrequency
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryPortInformationProcess(
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQuerySection(
	_In_ HANDLE SectionHandle,
	_In_ SECTION_INFORMATION_CLASS SectionInformationClass,
	_Out_ PVOID SectionInformation,
	_In_ SIZE_T SectionInformationLength,
	_Out_opt_ PSIZE_T ReturnLength
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQuerySecurityAttributesToken(
	_In_ HANDLE TokenHandle,
	_In_ PUNICODE_STRING Attributes,
	_In_ ULONG NumberOfAttributes,
	_Out_ PVOID Buffer, // PTOKEN_SECURITY_ATTRIBUTES_INFORMATION
	_In_ ULONG Length,
	_Out_ PULONG ReturnLength
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQuerySystemEnvironmentValue(
	_In_ PUNICODE_STRING VariableName,
	_Out_ PWSTR VariableValue,
	_In_ USHORT ValueLength,
	_Out_opt_ PUSHORT ReturnLength
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQuerySystemEnvironmentValueEx(
	_In_ PUNICODE_STRING VariableName,
	_In_ LPGUID VendorGuid,
	_Out_opt_ PVOID Value,
	_Inout_ PULONG ValueLength,
	_Out_opt_ PULONG Attributes
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQuerySystemInformation(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Out_opt_ PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Out_opt_ PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQuerySystemTime(
	_Out_ PLARGE_INTEGER SystemTime
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryTimerResolution(
	_Out_ PULONG MaximumTime,
	_Out_ PULONG MinimumTime,
	_Out_ PULONG CurrentTime
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueryWnfStateNameInformation(
	_In_ PCWNF_STATE_NAME StateName,
	_In_ WNF_STATE_NAME_INFORMATION NameInfoClass,
	_In_opt_ const VOID *ExplicitScope,
	_Out_ PVOID InfoBuffer,
	_In_ ULONG InfoBufferSize
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueueApcThread(
	_In_ HANDLE ThreadHandle,
	_In_ PPS_APC_ROUTINE ApcRoutine,
	_In_opt_ PVOID ApcArgument1,
	_In_opt_ PVOID ApcArgument2,
	_In_opt_ PVOID ApcArgument3
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQueueApcThreadEx(
	_In_ HANDLE ThreadHandle,
	_In_opt_ HANDLE UserApcReserveHandle,
	_In_ PPS_APC_ROUTINE ApcRoutine,
	_In_opt_ PVOID ApcArgument1,
	_In_opt_ PVOID ApcArgument2,
	_In_opt_ PVOID ApcArgument3
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwRaiseException(
	_In_ PEXCEPTION_RECORD ExceptionRecord,
	_In_ PCONTEXT ContextRecord,
	_In_ BOOLEAN FirstChance
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwRaiseHardError(
	_In_ NTSTATUS ErrorStatus,
	_In_ ULONG NumberOfParameters,
	_In_ ULONG UnicodeStringParameterMask,
	_In_ PULONG_PTR Parameters,
	_In_ ULONG ValidResponseOptions,
	_Out_ PULONG Response
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwReadFileScatter(
	_In_ HANDLE FileHandle,
	_In_opt_ HANDLE Event,
	_In_opt_ PIO_APC_ROUTINE ApcRoutine,
	_In_opt_ PVOID ApcContext,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_ PFILE_SEGMENT_ELEMENT SegmentArray,
	_In_ ULONG Length,
	_In_opt_ PLARGE_INTEGER ByteOffset,
	_In_opt_ PULONG Key
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwRegisterThreadTerminatePort(
	_In_ HANDLE PortHandle
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwReleaseCMFViewOwnership(
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwReleaseKeyedEvent(
	_In_ HANDLE KeyedEventHandle,
	_In_ PVOID KeyValue,
	_In_ BOOLEAN Alertable,
	_In_opt_ PLARGE_INTEGER Timeout
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwReleaseMutant(
	_In_ HANDLE MutantHandle,
	_Out_opt_ PLONG PreviousCount
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwReleaseSemaphore(
	_In_ HANDLE SemaphoreHandle,
	_In_ LONG ReleaseCount,
	_Out_opt_ PLONG PreviousCount
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwReleaseWorkerFactoryWorker(
	_In_ HANDLE WorkerFactoryHandle
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwRemoveIoCompletion(
	_In_ HANDLE IoCompletionHandle,
	_Out_ PVOID *KeyContext,
	_Out_ PVOID *ApcContext,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_ PLARGE_INTEGER Timeout
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwRemoveIoCompletionEx(
	_In_ HANDLE IoCompletionHandle,
	PFILE_IO_COMPLETION_INFORMATION IoCompletionInformation,
	_In_ ULONG Count,
	_Out_ PULONG NumEntriesRemoved,
	_In_opt_ PLARGE_INTEGER Timeout,
	_In_ BOOLEAN Alertable
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwRemoveProcessDebug(
	_In_ HANDLE ProcessHandle,
	_In_ HANDLE DebugObjectHandle
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwRenameTransactionManager(
	_In_ PUNICODE_STRING LogFileName,
	_In_ LPGUID ExistingTransactionManagerGuid
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwReplaceKey(
	_In_ POBJECT_ATTRIBUTES NewFile,
	_In_ HANDLE TargetHandle,
	_In_ POBJECT_ATTRIBUTES OldFile
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwReplacePartitionUnit(
	_In_ PUNICODE_STRING TargetInstancePath,
	_In_ PUNICODE_STRING SpareInstancePath,
	_In_ ULONG Flags
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwRequestDeviceWakeup(
	_In_ HANDLE Device
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwRequestWakeupLatency(
	_In_ LATENCY_TIME latency
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwResetEvent(
	_In_ HANDLE EventHandle,
	_Out_opt_ PLONG PreviousState
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwResetWriteWatch(
	_In_ HANDLE ProcessHandle,
	_In_ PVOID BaseAddress,
	_In_ SIZE_T RegionSize
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwResumeProcess(
	_In_ HANDLE ProcessHandle
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwRevertContainerImpersonation(
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSaveMergedKeys(
	_In_ HANDLE HighPrecedenceKeyHandle,
	_In_ HANDLE LowPrecedenceKeyHandle,
	_In_ HANDLE FileHandle
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSerializeBoot(
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetBootEntryOrder(
	_In_ PULONG Ids,
	_In_ ULONG Count
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetCachedSigningLevel(
	_In_ ULONG Flags,
	_In_ SE_SIGNING_LEVEL InputSigningLevel,
	_In_ PHANDLE SourceFiles,
	_In_ ULONG SourceFileCount,
	_In_opt_ HANDLE TargetFile
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetContextThread(
	_In_ HANDLE ThreadHandle,
	_In_ PCONTEXT ThreadContext
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetDebugFilterState(
	_In_ ULONG ComponentId,
	_In_ ULONG Level,
	_In_ BOOLEAN State
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetDefaultLocale(
	_In_ BOOLEAN UserProfile,
	_In_ LCID DefaultLocaleId
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetDefaultUILanguage(
	_In_ LANGID DefaultUILanguageId
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetDriverEntryOrder(
	_In_ PULONG Ids,
	_In_ ULONG Count
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetEventBoostPriority(
	_In_ HANDLE EventHandle
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetHighEventPair(
	_In_ HANDLE EventPairHandle
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetHighWaitLowEventPair(
	_In_ HANDLE EventPairHandle
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetIRTimer(
	_In_ HANDLE TimerHandle,
	_In_opt_ PLARGE_INTEGER DueTime
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetInformationDebugObject(
	_In_ HANDLE DebugObjectHandle,
	_In_ DEBUGOBJECTINFOCLASS DebugObjectInformationClass,
	_In_ PVOID DebugInformation,
	_In_ ULONG DebugInformationLength,
	_Out_opt_ PULONG ReturnLength
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetInformationObject(
	_In_ HANDLE Handle,
	_In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
	_In_ PVOID ObjectInformation,
	_In_ ULONG ObjectInformationLength
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetInformationProcess(
	_In_ HANDLE ProcessHandle,
	_In_ PROCESSINFOCLASS ProcessInformationClass,
	_In_ PVOID ProcessInformation,
	_In_ ULONG ProcessInformationLength
	);

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_ 
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetInformationVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_In_ VIRTUAL_MEMORY_INFORMATION_CLASS VmInformationClass,
	_In_ ULONG_PTR NumberOfEntries,
	_In_reads_(NumberOfEntries) PMEMORY_RANGE_ENTRY VirtualAddresses,
	_In_reads_bytes_(VmInformationLength) PVOID VmInformation,
	_In_ ULONG VmInformationLength
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetIntervalProfile(
	_In_ ULONG Interval,
	_In_ KPROFILE_SOURCE Source
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetIoCompletion(
	_In_ HANDLE IoCompletionHandle,
	_In_opt_ PVOID KeyContext,
	_In_opt_ PVOID ApcContext,
	_In_ NTSTATUS IoStatus,
	_In_ ULONG_PTR IoStatusInformation
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetIoCompletionEx(
	_In_ HANDLE IoCompletionHandle,
	_In_ HANDLE IoCompletionPacketHandle,
	_In_opt_ PVOID KeyContext,
	_In_opt_ PVOID ApcContext,
	_In_ NTSTATUS IoStatus,
	_In_ ULONG_PTR IoStatusInformation
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetLdtEntries(
	_In_ ULONG Selector0,
	_In_ ULONG Entry0Low,
	_In_ ULONG Entry0Hi,
	_In_ ULONG Selector1,
	_In_ ULONG Entry1Low,
	_In_ ULONG Entry1Hi
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetLowEventPair(
	_In_ HANDLE EventPairHandle
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetLowWaitHighEventPair(
	_In_ HANDLE EventPairHandle
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetSystemEnvironmentValue(
	_In_ PUNICODE_STRING VariableName,
	_In_ PUNICODE_STRING VariableValue
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetSystemEnvironmentValueEx(
	_In_ PUNICODE_STRING VariableName,
	_In_ LPGUID VendorGuid,
	_In_ PVOID Value,
	_In_ ULONG ValueLength,
	_In_ ULONG Attributes
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetSystemInformation(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_In_ PVOID SystemInformation,
	_In_ ULONG SystemInformationLength
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetSystemPowerState(
	_In_ POWER_ACTION SystemAction,
	_In_ SYSTEM_POWER_STATE LightestSystemState,
	_In_ ULONG Flags // POWER_ACTION_* flags
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetSystemTime(
	_In_opt_ PLARGE_INTEGER SystemTime,
	_Out_opt_ PLARGE_INTEGER PreviousTime
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetThreadExecutionState(
	_In_ EXECUTION_STATE NewFlags, // ES_* flags
	_Out_ EXECUTION_STATE *PreviousFlags
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetTimerResolution(
	_In_ ULONG DesiredTime,
	_In_ BOOLEAN SetResolution,
	_Out_ PULONG ActualTime
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetUuidSeed(
	_In_ PCHAR Seed
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetWnfProcessNotificationEvent(
	_In_ HANDLE NotificationEvent
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwShutdownWorkerFactory(
	_In_ HANDLE WorkerFactoryHandle,
	_Inout_ volatile LONG *PendingWorkerCount
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSignalAndWaitForSingleObject(
	_In_ HANDLE SignalHandle,
	_In_ HANDLE WaitHandle,
	_In_ BOOLEAN Alertable,
	_In_opt_ PLARGE_INTEGER Timeout
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwStartProfile(
	_In_ HANDLE ProfileHandle
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwStopProfile(
	_In_ HANDLE ProfileHandle
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSuspendProcess(
	_In_ HANDLE ProcessHandle
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSystemDebugControl(
	_In_ SYSDBG_COMMAND Command,
	_Inout_opt_ PVOID InputBuffer,
	_In_ ULONG InputBufferLength,
	_Out_opt_ PVOID OutputBuffer,
	_In_ ULONG OutputBufferLength,
	_Out_opt_ PULONG ReturnLength
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwTerminateJobObject(
	_In_ HANDLE JobHandle,
	_In_ NTSTATUS ExitStatus
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwTerminateThread(
	_In_opt_ HANDLE ThreadHandle,
	_In_ NTSTATUS ExitStatus
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwTestAlert(
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwThawRegistry(
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwTraceEvent(
	_In_ HANDLE TraceHandle,
	_In_ ULONG Flags,
	_In_ ULONG FieldSize,
	_In_ PVOID Fields
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwTranslateFilePath(
	_In_ PFILE_PATH InputFilePath,
	_In_ ULONG OutputType,
	_Out_opt_ PFILE_PATH OutputFilePath,
	_Inout_opt_ PULONG OutputFilePathLength
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwUmsThreadYield(
	_In_ PVOID SchedulerParam
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwUnloadKey(
	_In_ POBJECT_ATTRIBUTES TargetKey
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwUnloadKey2(
	_In_ POBJECT_ATTRIBUTES TargetKey,
	_In_ ULONG Flags
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwUnloadKeyEx(
	_In_ POBJECT_ATTRIBUTES TargetKey,
	_In_opt_ HANDLE Event
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwUnlockVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID *BaseAddress,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG MapType
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwUnmapViewOfSectionEx(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_In_ ULONG Flags
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwUnsubscribeWnfStateChange(
	_In_ PCWNF_STATE_NAME StateName
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwWaitForAlertByThreadId(
	_In_ PVOID Address,
	_In_opt_ PLARGE_INTEGER Timeout
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwWaitForDebugEvent(
	_In_ HANDLE DebugObjectHandle,
	_In_ BOOLEAN Alertable,
	_In_opt_ PLARGE_INTEGER Timeout,
	_Out_ PVOID WaitStateChange
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwWaitForKeyedEvent(
	_In_ HANDLE KeyedEventHandle,
	_In_ PVOID KeyValue,
	_In_ BOOLEAN Alertable,
	_In_opt_ PLARGE_INTEGER Timeout
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwWaitForMultipleObjects(
	_In_ ULONG Count,
	_In_ HANDLE Handles[],
	_In_ WAIT_TYPE WaitType,
	_In_ BOOLEAN Alertable,
	_In_opt_ PLARGE_INTEGER Timeout
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwWaitForMultipleObjects32(
	_In_ ULONG Count,
	_In_ LONG Handles[],
	_In_ WAIT_TYPE WaitType,
	_In_ BOOLEAN Alertable,
	_In_opt_ PLARGE_INTEGER Timeout
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwWaitForWorkViaWorkerFactory(
	_In_ HANDLE WorkerFactoryHandle,
	_Out_ struct _FILE_IO_COMPLETION_INFORMATION *MiniPacket,
	_In_ ULONG NumberOfMiniPackets,
	_Out_ PULONG NumberOfMiniPacketsReturned,
	_In_opt_ PHANDLE Handles,
	_In_ PULONG Flags
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwWaitHighEventPair(
	_In_ HANDLE EventPairHandle
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwWaitLowEventPair(
	_In_ HANDLE EventPairHandle
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwWorkerFactoryWorkerReady(
	_In_ HANDLE WorkerFactoryHandle
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwWriteFileGather(
	_In_ HANDLE FileHandle,
	_In_opt_ HANDLE Event,
	_In_opt_ PIO_APC_ROUTINE ApcRoutine,
	_In_opt_ PVOID ApcContext,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_ PFILE_SEGMENT_ELEMENT SegmentArray,
	_In_ ULONG Length,
	_In_opt_ PLARGE_INTEGER ByteOffset,
	_In_opt_ PULONG Key
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwWriteVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_In_ PVOID Buffer,
	_In_ SIZE_T BufferSize,
	_Out_opt_ PSIZE_T NumberOfBytesWritten
	);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwYieldExecution(
	);

// DBGK

typedef enum _DBG_STATE
{
	DbgIdle,
	DbgReplyPending,
	DbgCreateThreadStateChange,
	DbgCreateProcessStateChange,
	DbgExitThreadStateChange,
	DbgExitProcessStateChange,
	DbgExceptionStateChange,
	DbgBreakpointStateChange,
	DbgSingleStepStateChange,
	DbgLoadDllStateChange,
	DbgUnloadDllStateChange
} DBG_STATE, *PDBG_STATE;

typedef struct _DBGKM_EXCEPTION
{
	EXCEPTION_RECORD ExceptionRecord;
	ULONG FirstChance;
} DBGKM_EXCEPTION, *PDBGKM_EXCEPTION;

typedef struct _DBGKM_CREATE_THREAD
{
	ULONG SubSystemKey;
	PVOID StartAddress;
} DBGKM_CREATE_THREAD, *PDBGKM_CREATE_THREAD;

typedef struct _DBGKM_CREATE_PROCESS
{
	ULONG SubSystemKey;
	HANDLE FileHandle;
	PVOID BaseOfImage;
	ULONG DebugInfoFileOffset;
	ULONG DebugInfoSize;
	DBGKM_CREATE_THREAD InitialThread;
} DBGKM_CREATE_PROCESS, *PDBGKM_CREATE_PROCESS;

typedef struct _DBGKM_EXIT_THREAD
{
	NTSTATUS ExitStatus;
} DBGKM_EXIT_THREAD, *PDBGKM_EXIT_THREAD;

typedef struct _DBGKM_EXIT_PROCESS
{
	NTSTATUS ExitStatus;
} DBGKM_EXIT_PROCESS, *PDBGKM_EXIT_PROCESS;

typedef struct _DBGKM_LOAD_DLL
{
	HANDLE FileHandle;
	PVOID BaseOfDll;
	ULONG DebugInfoFileOffset;
	ULONG DebugInfoSize;
	PVOID NamePointer;
} DBGKM_LOAD_DLL, *PDBGKM_LOAD_DLL;

typedef struct _DBGKM_UNLOAD_DLL
{
	PVOID BaseAddress;
} DBGKM_UNLOAD_DLL, *PDBGKM_UNLOAD_DLL;

typedef struct _DBGUI_CREATE_THREAD
{
	HANDLE HandleToThread;
	DBGKM_CREATE_THREAD NewThread;
} DBGUI_CREATE_THREAD, *PDBGUI_CREATE_THREAD;

typedef struct _DBGUI_CREATE_PROCESS
{
	HANDLE HandleToProcess;
	HANDLE HandleToThread;
	DBGKM_CREATE_PROCESS NewProcess;
} DBGUI_CREATE_PROCESS, *PDBGUI_CREATE_PROCESS;

typedef struct _DBGUI_WAIT_STATE_CHANGE
{
	DBG_STATE NewState;
	CLIENT_ID AppClientId;
	union
	{
		DBGKM_EXCEPTION Exception;
		DBGUI_CREATE_THREAD CreateThread;
		DBGUI_CREATE_PROCESS CreateProcessInfo;
		DBGKM_EXIT_THREAD ExitThread;
		DBGKM_EXIT_PROCESS ExitProcess;
		DBGKM_LOAD_DLL LoadDll;
		DBGKM_UNLOAD_DLL UnloadDll;
	} StateInfo;
} DBGUI_WAIT_STATE_CHANGE, *PDBGUI_WAIT_STATE_CHANGE;


// EX

typedef struct _EX_PUSH_LOCK_WAIT_BLOCK *PEX_PUSH_LOCK_WAIT_BLOCK;

NTKERNELAPI
VOID
FASTCALL
ExfUnblockPushLock(
	_Inout_ PEX_PUSH_LOCK PushLock,
	_Inout_opt_ PEX_PUSH_LOCK_WAIT_BLOCK WaitBlock
	);

typedef struct _HANDLE_TABLE HANDLE_TABLE, *PHANDLE_TABLE;

typedef BOOLEAN(NTAPI *PEX_ENUM_HANDLE_CALLBACK)(
	_Inout_ PHANDLE_TABLE_ENTRY HandleTableEntry,
	_In_ HANDLE Handle,
	_In_ PVOID Context
	);

NTKERNELAPI
BOOLEAN
NTAPI
ExEnumHandleTable(
	_In_ PHANDLE_TABLE HandleTable,
	_In_ PEX_ENUM_HANDLE_CALLBACK EnumHandleProcedure,
	_Inout_ PVOID Context,
	_Out_opt_ PHANDLE Handle
	);

// This is from XP era times, don't use it
typedef struct _BOOT_ENTRY
{
	ULONG Version;
	ULONG Length;
	ULONG Id;
	ULONG Attributes;
	ULONG FriendlyNameOffset;
	ULONG BootFilePathOffset;
	ULONG OsOptionsLength;
	UCHAR OsOptions[ANYSIZE_ARRAY];
	//WCHAR FriendlyName[ANYSIZE_ARRAY];
	//FILE_PATH BootFilePath;
} BOOT_ENTRY, *PBOOT_ENTRY;

typedef struct _EFI_DRIVER_ENTRY
{
	ULONG Version;
	ULONG Length;
	ULONG Id;
	ULONG FriendlyNameOffset;
	ULONG DriverFilePathOffset;
	//WCHAR FriendlyName[ANYSIZE_ARRAY];
	//FILE_PATH DriverFilePath;
} EFI_DRIVER_ENTRY, *PEFI_DRIVER_ENTRY;

typedef struct _BOOT_OPTIONS
{
	ULONG Version;
	ULONG Length;
	ULONG Timeout;
	ULONG CurrentBootEntryId;
	ULONG NextBootEntryId;
	WCHAR HeadlessRedirection[ANYSIZE_ARRAY];
} BOOT_OPTIONS, *PBOOT_OPTIONS;

#define HARDERROR_OVERRIDE_ERRORMODE		0x10000000

typedef enum _HARDERROR_RESPONSE_OPTION
{
	OptionAbortRetryIgnore,
	OptionOk,
	OptionOkCancel,
	OptionRetryCancel,
	OptionYesNo,
	OptionYesNoCancel,
	OptionShutdownSystem,
	OptionOkNoWait,
	OptionCancelTryContinue
} HARDERROR_RESPONSE_OPTION, *PHARDERROR_RESPONSE_OPTION;

typedef enum _HARDERROR_RESPONSE
{
	ResponseReturnToCaller,
	ResponseNotHandled,
	ResponseAbort,
	ResponseCancel,
	ResponseIgnore,
	ResponseNo,
	ResponseOk,
	ResponseRetry,
	ResponseYes,
	ResponseTryAgain,
	ResponseContinue
} HARDERROR_RESPONSE, *PHARDERROR_RESPONSE;

// IO

extern POBJECT_TYPE *IoDriverObjectType;

typedef enum _WORKERFACTORYINFOCLASS
{
	WorkerFactoryTimeout,
	WorkerFactoryRetryTimeout,
	WorkerFactoryIdleTimeout,
	WorkerFactoryBindingCount,
	WorkerFactoryThreadMinimum,
	WorkerFactoryThreadMaximum,
	WorkerFactoryPaused,
	WorkerFactoryBasicInformation,
	WorkerFactoryAdjustThreadGoal,
	WorkerFactoryCallbackType,
	WorkerFactoryStackInformation, // 10
	WorkerFactoryThreadBasePriority,
	WorkerFactoryTimeoutWaiters, // since THRESHOLD
	WorkerFactoryFlags,
	WorkerFactoryThreadSoftMaximum,
	MaxWorkerFactoryInfoClass
} WORKERFACTORYINFOCLASS, *PWORKERFACTORYINFOCLASS;

// KE

typedef VOID(NTAPI *PKNORMAL_ROUTINE)(
	_In_ PVOID NormalContext,
	_In_ PVOID SystemArgument1,
	_In_ PVOID SystemArgument2
	);

typedef VOID KKERNEL_ROUTINE(
	_In_ PRKAPC Apc,
	_Inout_ PKNORMAL_ROUTINE *NormalRoutine,
	_Inout_ PVOID *NormalContext,
	_Inout_ PVOID *SystemArgument1,
	_Inout_ PVOID *SystemArgument2
);

typedef KKERNEL_ROUTINE(NTAPI *PKKERNEL_ROUTINE);

typedef VOID(NTAPI *PKRUNDOWN_ROUTINE)(
	_In_ PRKAPC Apc
	);

NTKERNELAPI
VOID
NTAPI
KeInitializeApc(
	_Out_ PRKAPC Apc,
	_In_ PRKTHREAD Thread,
	_In_ KAPC_ENVIRONMENT Environment,
	_In_ PKKERNEL_ROUTINE KernelRoutine,
	_In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
	_In_opt_ PKNORMAL_ROUTINE NormalRoutine,
	_In_opt_ KPROCESSOR_MODE ProcessorMode,
	_In_opt_ PVOID NormalContext
	);

NTKERNELAPI
BOOLEAN
NTAPI
KeInsertQueueApc(
	_Inout_ PRKAPC Apc,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2,
	_In_ KPRIORITY Increment
	);

NTKERNELAPI
BOOLEAN
NTAPI
KeTestAlertThread(
	_In_ KPROCESSOR_MODE AlertMode
	);

// LDR

typedef struct _LDR_RESOURCE_INFO
{
	ULONG_PTR Type;
	ULONG_PTR Name;
	ULONG_PTR Language;
} LDR_RESOURCE_INFO, *PLDR_RESOURCE_INFO;

typedef NTSTATUS(NTAPI *PUSER_THREAD_START_ROUTINE)(
	_In_ PVOID Parameter
	);

// LPC/ALPC (enough to get the driver to compile, but if you actually want to use it use ntlpcapi.h from Process Hacker)

typedef struct _PORT_MESSAGE
{
	union
	{
		struct
		{
			SHORT DataLength;
			SHORT TotalLength;
		} s1;
		ULONG Length;
	} u1;
	union
	{
		struct
		{
			SHORT Type;
			SHORT DataInfoOffset;
		} s2;
		ULONG ZeroInit;
	} u2;
	union
	{
		CLIENT_ID ClientId;
		double DoNotUseThisField;
	};
	ULONG MessageId;
	union
	{
		SIZE_T ClientViewSize; // only valid for LPC_CONNECTION_REQUEST messages
		ULONG CallbackId; // only valid for LPC_REQUEST messages
	};
} PORT_MESSAGE, *PPORT_MESSAGE;

typedef struct _PORT_VIEW
{
	ULONG Length;
	HANDLE SectionHandle;
	ULONG SectionOffset;
	SIZE_T ViewSize;
	PVOID ViewBase;
	PVOID ViewRemoteBase;
} PORT_VIEW, *PPORT_VIEW;

typedef struct _REMOTE_PORT_VIEW
{
	ULONG Length;
	SIZE_T ViewSize;
	PVOID ViewBase;
} REMOTE_PORT_VIEW, *PREMOTE_PORT_VIEW;

typedef enum _ALPC_PORT_INFORMATION_CLASS
{
	AlpcBasicInformation, // q: out ALPC_BASIC_INFORMATION
	AlpcPortInformation, // s: in ALPC_PORT_ATTRIBUTES
	AlpcAssociateCompletionPortInformation, // s: in ALPC_PORT_ASSOCIATE_COMPLETION_PORT
	AlpcConnectedSIDInformation, // q: in SID
	AlpcServerInformation, // q: inout ALPC_SERVER_INFORMATION
	AlpcMessageZoneInformation, // s: in ALPC_PORT_MESSAGE_ZONE_INFORMATION // no-op since 8.1
	AlpcRegisterCompletionListInformation, // s: in ALPC_PORT_COMPLETION_LIST_INFORMATION
	AlpcUnregisterCompletionListInformation, // s: VOID
	AlpcAdjustCompletionListConcurrencyCountInformation, // s: in ULONG
	AlpcRegisterCallbackInformation, // kernel-mode only
	AlpcCompletionListRundownInformation, // s: VOID
	AlpcWaitForPortReferences
} ALPC_PORT_INFORMATION_CLASS;

typedef enum _ALPC_MESSAGE_INFORMATION_CLASS
{
	AlpcMessageSidInformation, // q: out SID
	AlpcMessageTokenModifiedIdInformation, // q: out LUID
	AlpcMessageDirectStatusInformation,
	AlpcMessageHandleInformation, // ALPC_MESSAGE_HANDLE_INFORMATION
	MaxAlpcMessageInfoClass
} ALPC_MESSAGE_INFORMATION_CLASS, *PALPC_MESSAGE_INFORMATION_CLASS;

typedef HANDLE ALPC_HANDLE, *PALPC_HANDLE;

// MM

NTKERNELAPI
NTSTATUS
NTAPI
MmCopyVirtualMemory(
	_In_ PEPROCESS FromProcess,
	_In_ CONST VOID *FromAddress,
	_In_ PEPROCESS ToProcess,
	_Out_ PVOID ToAddress,
	_In_ SIZE_T BufferSize,
	_In_ KPROCESSOR_MODE PreviousMode,
	_Out_ PSIZE_T NumberOfBytesCopied
	);

NTKERNELAPI
NTSTATUS
NTAPI
MmCreateSection(
	_Out_ PVOID *SectionObject,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ PLARGE_INTEGER InputMaximumSize,
	_In_ ULONG Win32SectionPageProtection,
	_In_ ULONG AllocationAttributes,
	_In_opt_ HANDLE FileHandle,
	_In_opt_ PFILE_OBJECT FileObject
	);

// OB

// These definitions are no longer correct, but they produce correct results.

#define OBJ_PROTECT_CLOSE 0x00000001
#define OBJ_HANDLE_ATTRIBUTES (OBJ_PROTECT_CLOSE | OBJ_INHERIT | OBJ_AUDIT_OBJECT_CLOSE)

// This attribute is now stored in the GrantedAccess field.
#define ObpAccessProtectCloseBit 0x2000000

#define ObpDecodeGrantedAccess(Access) \
	((Access) & ~ObpAccessProtectCloseBit)

typedef struct _OBJECT_CREATE_INFORMATION OBJECT_CREATE_INFORMATION, *POBJECT_CREATE_INFORMATION;

#define OBJECT_TO_OBJECT_HEADER(Object) CONTAINING_RECORD((Object), OBJECT_HEADER, Body)

NTKERNELAPI
POBJECT_TYPE
NTAPI
ObGetObjectType(
	_In_ PVOID Object
	);

NTKERNELAPI
NTSTATUS
NTAPI
ObOpenObjectByName(
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ POBJECT_TYPE ObjectType,
	_In_ KPROCESSOR_MODE PreviousMode,
	_In_opt_ PACCESS_STATE AccessState,
	_In_opt_ ACCESS_MASK DesiredAccess,
	_In_ PVOID ParseContext,
	_Out_ PHANDLE Handle
	);

NTKERNELAPI
NTSTATUS
NTAPI
ObSetHandleAttributes(
	_In_ HANDLE Handle,
	_In_ POBJECT_HANDLE_FLAG_INFORMATION HandleFlags,
	_In_ KPROCESSOR_MODE PreviousMode
	);

NTKERNELAPI
NTSTATUS
ObCloseHandle(
	_In_ _Post_ptr_invalid_ HANDLE Handle,
	_In_ KPROCESSOR_MODE PreviousMode
	);

// PS

NTKERNELAPI
NTSTATUS
NTAPI
PsLookupProcessThreadByCid(
	_In_ PCLIENT_ID ClientId,
	_Out_opt_ PEPROCESS *Process,
	_Out_ PETHREAD *Thread
	);

NTKERNELAPI
NTSTATUS
PsGetContextThread(
	_In_ PETHREAD Thread,
	_Inout_ PCONTEXT ThreadContext,
	_In_ KPROCESSOR_MODE Mode
	);

NTKERNELAPI
NTSTATUS
PsSetContextThread(
	_In_ PETHREAD Thread,
	_In_ PCONTEXT ThreadContext,
	_In_ KPROCESSOR_MODE Mode
	);

NTKERNELAPI
PVOID
NTAPI
PsGetCurrentProcessWow64Process(
	);

NTKERNELAPI
PVOID
NTAPI
PsGetThreadWin32Thread(
	_In_ PETHREAD Thread
	);

NTKERNELAPI
NTSTATUS
PsResumeProcess(
	_In_ PEPROCESS Process
	);

NTKERNELAPI
NTSTATUS
PsSuspendProcess(
	_In_ PEPROCESS Process
	);

NTKERNELAPI
ULONG
PsGetProcessSessionId(
	_In_ PEPROCESS Process
	);

NTKERNELAPI
ULONG
PsGetProcessSessionIdEx(
	_In_ PEPROCESS Process
	);

_IRQL_requires_max_(DISPATCH_LEVEL)
NTKERNELAPI
HANDLE
PsGetProcessId(
	_In_ PEPROCESS Process
	);

NTKERNELAPI
PPEB
PsGetProcessPeb(
	_In_ PEPROCESS Process
	);

NTKERNELAPI
PVOID
PsGetProcessWow64Process(
	_In_ PEPROCESS Process
	);

NTKERNELAPI
PCHAR
PsGetProcessImageFileName(
	_In_ PEPROCESS Process
	);

_IRQL_requires_max_(DISPATCH_LEVEL)
NTKERNELAPI
HANDLE
PsGetThreadId(
	_In_ PETHREAD Thread
	);

NTKERNELAPI
PEPROCESS
PsGetThreadProcess(
	_In_ PETHREAD Thread
	);

NTKERNELAPI
PEPROCESS
PsGetCurrentThreadProcess(
	);

NTKERNELAPI
HANDLE
PsGetThreadProcessId(
	_In_ PETHREAD Thread
	);

NTKERNELAPI
HANDLE
PsGetCurrentThreadProcessId(
	);

NTKERNELAPI
PVOID
PsGetThreadTeb(
	_In_ PETHREAD Thread
	);

NTKERNELAPI
PVOID
PsGetCurrentThreadTeb(
	);

#if NTDDI_VERSION >= NTDDI_VISTA
NTKERNELAPI
BOOLEAN
PsIsProtectedProcess(
	_In_ PEPROCESS Process
	);
#endif

#if NTDDI_VERSION >= NTDDI_WINBLUE
NTKERNELAPI
BOOLEAN
PsIsProtectedProcessLight(
	_In_ PEPROCESS Process
	);
#endif

_Must_inspect_result_
_IRQL_requires_max_(APC_LEVEL)
NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId(
	_In_ HANDLE ProcessId,
	_Outptr_ PEPROCESS *Process
	);

NTKERNELAPI
HANDLE
PsGetProcessWin32WindowStation(
	_In_ PEPROCESS Process
	);

NTKERNELAPI
VOID
PsSetProcessWindowStation(
	_Out_ PEPROCESS Process,
	_In_ HANDLE Win32WindowStation
	);

typedef struct _EJOB *PEJOB;

extern POBJECT_TYPE *PsJobType;

NTKERNELAPI
PVOID
NTAPI
PsGetProcessDebugPort(
	_In_ PEPROCESS Process
	);

NTKERNELAPI
PEJOB
NTAPI
PsGetProcessJob(
	_In_ PEPROCESS Process
	);

NTKERNELAPI
NTSTATUS
NTAPI
PsAcquireProcessExitSynchronization(
	_In_ PEPROCESS Process
	);

NTKERNELAPI
VOID
NTAPI
PsReleaseProcessExitSynchronization(
	_In_ PEPROCESS Process
	);

// RTL

NTSYSAPI
VOID
NTAPI
RtlAvlRemoveNode(
	_Inout_ PMM_AVL_TABLE Table,
	_In_ PMMADDRESS_NODE Node
	);

#define UNW_FLAG_NHANDLER 0x0
#define UNW_FLAG_EHANDLER 0x1
#define UNW_FLAG_UHANDLER 0x2
#define UNW_FLAG_CHAININFO 0x4

NTSYSAPI
PEXCEPTION_ROUTINE
NTAPI
RtlVirtualUnwind(
	_In_ ULONG HandlerType,
	_In_ DWORD64 ImageBase,
	_In_ DWORD64 ControlPc,
	_In_ PRUNTIME_FUNCTION FunctionEntry,
	_Inout_ PCONTEXT ContextRecord,
	_Out_ PVOID *HandlerData,
	_Out_ PDWORD64 EstablisherFrame,
	_Inout_opt_ PKNONVOLATILE_CONTEXT_POINTERS ContextPointers
	);

NTSYSAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(
	_In_ PVOID ImageBase
	);

NTSYSAPI
PVOID
NTAPI
RtlImageDirectoryEntryToData(
	_In_ PVOID ImageBase,
	_In_ BOOLEAN MappedAsImage,
	_In_ USHORT DirectoryEntry,
	_Out_ PULONG Size
	);

NTSYSAPI
PRUNTIME_FUNCTION
NTAPI
RtlLookupFunctionEntry (
	_In_ DWORD64 ControlPc,
	_Out_ PDWORD64 ImageBase,
	_Inout_opt_ PUNWIND_HISTORY_TABLE HistoryTable
	);

// RtlWalkFrameChain (ntddk.h)
// Sensible limit that may or may not correspond to the actual Windows value.
#define RTL_WALK_MAX_STACK_DEPTH	128

// These are not bitmask flags - choose one
#define RTL_WALK_KERNEL_MODE_STACK		0x00000000
#define RTL_WALK_USER_MODE_STACK		0x00000001
#define RTL_WALK_TRACE_HANDLES			0x00000300

}
