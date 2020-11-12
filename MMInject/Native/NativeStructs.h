#pragma once

#include "NativeEnums.h"
#include <ntimage.h>

#if NTDDI_VERSION >= NTDDI_WIN10
#include "NativeStructs10.h"
#elif NTDDI_VERSION == NTDDI_WINBLUE
#include "NativeStructs81.h"
#elif NTDDI_VERSION == NTDDI_WIN7
#include "NativeStructs7.h"
#else
#error Unsupported OS build version
#endif

#define MAKEINTRESOURCEW(i) ((PWCH)((ULONG_PTR)((USHORT)(i))))

typedef struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE
{
	PULONG_PTR ServiceTableBase;
	PULONG ServiceCounterTableBase;
	ULONG_PTR NumberOfServices;
	PUCHAR ParamTableBase;
} SYSTEM_SERVICE_DESCRIPTOR_TABLE, *PSYSTEM_SERVICE_DESCRIPTOR_TABLE;

typedef union _PS_PROTECTION {
	UCHAR Level;
	struct
	{
		PS_PROTECTED_TYPE Type : 3;
		BOOLEAN Audit : 1;
		PS_PROTECTED_SIGNER Signer : 4;
	} Flags;
} PS_PROTECTION, *PPS_PROTECTION;

typedef struct _EPROCESS_FLAGS // Correct for <= RS2. In RS3+ this contains nothing relevant
{
	UCHAR CreateReported : 1;
	UCHAR NoDebugInherit : 1;
	UCHAR ProcessExiting : 1;
	UCHAR ProcessDelete : 1;
	UCHAR ControlFlowGuardEnabled : 1;
	UCHAR VmDeleted : 1;
	UCHAR OutswapEnabled : 1;
	UCHAR Outswapped : 1;
	UCHAR FailFastOnCommitFail : 1;
	UCHAR Wow64VaSpace4Gb : 1;
	UCHAR AddressSpaceInitialized : 2;
	UCHAR SetTimerResolution : 1;
	UCHAR BreakOnTermination : 1;
	UCHAR DeprioritizeViews : 1;
	UCHAR WriteWatch : 1;
	UCHAR ProcessInSession : 1;
	UCHAR OverrideAddressSpace : 1;
	UCHAR HasAddressSpace : 1;
	UCHAR LaunchPrefetched : 1;
	UCHAR Background : 1;
	UCHAR VmTopDown : 1;
	UCHAR ImageNotifyDone : 1;
	UCHAR PdeUpdateNeeded : 1;
	UCHAR VdmAllowed : 1;
	UCHAR ProcessRundown : 1;
	UCHAR ProcessInserted : 1;
	UCHAR DefaultIoPriority : 3;
	UCHAR ProcessSelfDelete : 1;
	UCHAR SetTimerResolutionLink : 1;
} EPROCESS_FLAGS, *PEPROCESS_FLAGS;

typedef struct _EPROCESS_FLAGS2 // Correct for <= RS2. In RS3 this contains nothing relevant
{
	unsigned int JobNotReallyActive : 1;
	unsigned int AccountingFolded : 1;
	unsigned int NewProcessReported : 1;
	unsigned int ExitProcessReported : 1;
	unsigned int ReportCommitChanges : 1;
	unsigned int LastReportMemory : 1;
	unsigned int ForceWakeCharge : 1;
	unsigned int CrossSessionCreate : 1;
	unsigned int NeedsHandleRundown : 1;
	unsigned int RefTraceEnabled : 1;
	unsigned int DisableDynamicCode : 1;
	unsigned int EmptyJobEvaluated : 1;
	unsigned int DefaultPagePriority : 3;
	unsigned int PrimaryTokenFrozen : 1;
	unsigned int ProcessVerifierTarget : 1;
	unsigned int StackRandomizationDisabled : 1;
	unsigned int AffinityPermanent : 1;
	unsigned int AffinityUpdateEnable : 1;
	unsigned int PropagateNode : 1;
	unsigned int ExplicitAffinity : 1;
	unsigned int ProcessExecutionState : 2;
	unsigned int DisallowStrippedImages : 1;
	unsigned int HighEntropyASLREnabled : 1;
	unsigned int ExtensionPointDisable : 1;
	unsigned int ForceRelocateImages : 1;
	unsigned int ProcessStateChangeRequest : 2;
	unsigned int ProcessStateChangeInProgress : 1;
	unsigned int DisallowWin32kSystemCalls : 1;
} EPROCESS_FLAGS2, *PEPROCESS_FLAGS2;

typedef struct _EPROCESS_FLAGS2_RS4_PLUS // RS4/RS5 version. Almost irrelevant, except for...
{
	unsigned int JobNotReallyActive : 1;
	unsigned int AccountingFolded : 1;
	unsigned int NewProcessReported : 1;
	unsigned int ExitProcessReported : 1;
	unsigned int ReportCommitChanges : 1;
	unsigned int LastReportMemory : 1;
	unsigned int ForceWakeCharge : 1;
	unsigned int CrossSessionCreate : 1;
	unsigned int NeedsHandleRundown : 1;
	unsigned int RefTraceEnabled : 1;
	unsigned int PicoCreated : 1;
	unsigned int EmptyJobEvaluated : 1;
	unsigned int DefaultPagePriority : 3;
	unsigned int PrimaryTokenFrozen : 1;
	unsigned int ProcessVerifierTarget : 1;
	unsigned int RestrictSetThreadContext : 1; // ...this guy
	unsigned int AffinityPermanent : 1;
	unsigned int AffinityUpdateEnable : 1;
	unsigned int PropagateNode : 1;
	unsigned int ExplicitAffinity : 1;
	unsigned int ProcessExecutionState : 2;
	unsigned int EnableReadVmLogging : 1;	// and maybe
	unsigned int EnableWriteVmLogging : 1;	// these two?
	unsigned int FatalAccessTerminationRequested : 1;
	unsigned int DisableSystemAllowedCpuSet : 1;
	unsigned int ProcessStateChangeRequest : 2;
	unsigned int ProcessStateChangeInProgress : 1;
	unsigned int InPrivate : 1;
} EPROCESS_FLAGS2_RS4_PLUS, *PEPROCESS_FLAGS2_RS4_PLUS;

typedef struct _EPROCESS_MITIGATION_FLAGS // Since RS3
{
	unsigned int ControlFlowGuardEnabled : 1;
	unsigned int ControlFlowGuardExportSuppressionEnabled : 1;
	unsigned int ControlFlowGuardStrict : 1;
	unsigned int DisallowStrippedImages : 1;
	unsigned int ForceRelocateImages : 1;
	unsigned int HighEntropyASLREnabled : 1;
	unsigned int StackRandomizationDisabled : 1;
	unsigned int ExtensionPointDisable : 1;
	unsigned int DisableDynamicCode : 1;
	unsigned int DisableDynamicCodeAllowOptOut : 1;
	unsigned int DisableDynamicCodeAllowRemoteDowngrade : 1;
	unsigned int AuditDisableDynamicCode : 1;
	unsigned int DisallowWin32kSystemCalls : 1;
	unsigned int AuditDisallowWin32kSystemCalls : 1;
	unsigned int EnableFilteredWin32kAPIs : 1;
	unsigned int AuditFilteredWin32kAPIs : 1;
	unsigned int DisableNonSystemFonts : 1;
	unsigned int AuditNonSystemFontLoading : 1;
	unsigned int PreferSystem32Images : 1;
	unsigned int ProhibitRemoteImageMap : 1;
	unsigned int AuditProhibitRemoteImageMap : 1;
	unsigned int ProhibitLowILImageMap : 1;
	unsigned int AuditProhibitLowILImageMap : 1;
	unsigned int SignatureMitigationOptIn : 1;
	unsigned int AuditBlockNonMicrosoftBinaries : 1;
	unsigned int AuditBlockNonMicrosoftBinariesAllowStore : 1;
	unsigned int LoaderIntegrityContinuityEnabled : 1;
	unsigned int AuditLoaderIntegrityContinuity : 1;
	unsigned int EnableModuleTamperingProtection : 1;
	unsigned int EnableModuleTamperingProtectionNoInherit : 1;
	unsigned int RestrictIndirectBranchPrediction : 1;
	unsigned int IsolateSecurityDomain : 1;
} EPROCESS_MITIGATION_FLAGS, *PEPROCESS_MITIGATION_FLAGS;

typedef struct _EPROCESS_MITIGATION_FLAGS2 // Since RS3
{
	unsigned int EnableExportAddressFilter : 1;
	unsigned int AuditExportAddressFilter : 1;
	unsigned int EnableExportAddressFilterPlus : 1;
	unsigned int AuditExportAddressFilterPlus : 1;
	unsigned int EnableRopStackPivot : 1;
	unsigned int AuditRopStackPivot : 1;
	unsigned int EnableRopCallerCheck : 1;
	unsigned int AuditRopCallerCheck : 1;
	unsigned int EnableRopSimExec : 1;
	unsigned int AuditRopSimExec : 1;
	unsigned int EnableImportAddressFilter : 1;
	unsigned int AuditImportAddressFilter : 1;
	unsigned int DisablePageCombine : 1; // Since 19H1
	unsigned int SpeculativeStoreBypassDisable : 1;
	unsigned int CetUserShadowStacks : 1;
} EPROCESS_MITIGATION_FLAGS2, *PEPROCESS_MITIGATION_FLAGS2;

typedef union _EXHANDLE {
	struct
	{
		int TagBits : 2;
		int Index : 30;
	} u;
	void *GenericHandleOverlay;
	ULONG_PTR Value;
} EXHANDLE, *PEXHANDLE;

#pragma warning(disable : 4214 4201)


typedef struct _HANDLE_TABLE_ENTRY // Size=16
{
	union {
		ULONG_PTR VolatileLowValue; // Size=8 Offset=0
		ULONG_PTR LowValue; // Size=8 Offset=0
		struct _HANDLE_TABLE_ENTRY_INFO *InfoTable; // Size=8 Offset=0
		struct
		{
			ULONG_PTR Unlocked : 1; // Size=8 Offset=0 BitOffset=0 BitCount=1
#ifdef _WIN64
			ULONG_PTR RefCnt : 16; // Size=8 Offset=0 BitOffset=1 BitCount=16
			ULONG_PTR Attributes : 3; // Size=8 Offset=0 BitOffset=17 BitCount=3
			ULONG_PTR ObjectPointerBits : 44; // Size=8 Offset=0 BitOffset=20 BitCount=44
#else
			ULONG_PTR Attributes : 2; // Size=8 Offset=0 BitOffset=17 BitCount=3
			ULONG_PTR ObjectPointerBits : 29; // Size=8 Offset=0 BitOffset=3 BitCount=29
#endif
		};
	};
	union {
		ULONG_PTR HighValue; // Size=8 Offset=8
		struct _HANDLE_TABLE_ENTRY *NextFreeHandleEntry; // Size=8 Offset=8
		union _EXHANDLE LeafHandleValue; // Size=8 Offset=8
		struct
		{
			ULONG GrantedAccessBits : 25; // Size=4 Offset=8 BitOffset=0 BitCount=25
			ULONG NoRightsUpgrade : 1; // Size=4 Offset=8 BitOffset=25 BitCount=1
			ULONG Spare : 6; // Size=4 Offset=8 BitOffset=26 BitCount=6
		};
	};
	ULONG TypeInfo; // Size=4 Offset=12
} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;


typedef struct _OBJECT_HEADER // Size=56
{
	ULONG_PTR PointerCount; // Size=8 Offset=0
	union {
		ULONG_PTR HandleCount; // Size=8 Offset=8
		void *NextToFree; // Size=8 Offset=8
	};
	void *Lock; // Size=8 Offset=16
	UCHAR TypeIndex; // Size=1 Offset=24
	union {
		UCHAR TraceFlags; // Size=1 Offset=25
		struct
		{
			UCHAR DbgRefTrace : 1; // Size=1 Offset=25 BitOffset=0 BitCount=1
			UCHAR DbgTracePermanent : 1; // Size=1 Offset=25 BitOffset=1 BitCount=1
		};
	};
	UCHAR InfoMask; // Size=1 Offset=26
	union {
		UCHAR Flags; // Size=1 Offset=27
		struct
		{
			UCHAR NewObject : 1; // Size=1 Offset=27 BitOffset=0 BitCount=1
			UCHAR KernelObject : 1; // Size=1 Offset=27 BitOffset=1 BitCount=1
			UCHAR KernelOnlyAccess : 1; // Size=1 Offset=27 BitOffset=2 BitCount=1
			UCHAR ExclusiveObject : 1; // Size=1 Offset=27 BitOffset=3 BitCount=1
			UCHAR PermanentObject : 1; // Size=1 Offset=27 BitOffset=4 BitCount=1
			UCHAR DefaultSecurityQuota : 1; // Size=1 Offset=27 BitOffset=5 BitCount=1
			UCHAR SingleHandleEntry : 1; // Size=1 Offset=27 BitOffset=6 BitCount=1
			UCHAR DeletedInline : 1; // Size=1 Offset=27 BitOffset=7 BitCount=1
		};
	};
	ULONG Spare; // Size=4 Offset=28
	union {
		struct _OBJECT_CREATE_INFORMATION *ObjectCreateInfo; // Size=8 Offset=32
		void *QuotaBlockCharged; // Size=8 Offset=32
	};
	void *SecurityDescriptor; // Size=8 Offset=40
	struct _QUAD Body; // Size=8 Offset=48
} OBJECT_HEADER, *POBJECT_HEADER;

typedef union _EX_FAST_REF // Size=8
{
	void *Object;
	struct
	{
		unsigned __int64 RefCnt : 4;
	};
	unsigned __int64 Value;
} EX_FAST_REF, *PEX_FAST_REF;

typedef struct _SEGMENT
{
	PVOID ControlArea;
	ULONG TotalNumberOfPtes;
	UCHAR SegmentFlags;
	ULONG64 NumberOfCommittedPages;
	ULONG64 SizeOfSegment;
	union
	{
		PVOID ExtendInfo;
		PVOID BasedAddress;
	} u1;
	ULONG64 u2;
	ULONG64 u3;
	PVOID PrototypePte;
} SEGMENT, *PSEGMENT;

typedef struct _CONTROL_AREA // Size=120
{
	struct _SEGMENT *Segment;
	struct _LIST_ENTRY ListHead;
	unsigned __int64 NumberOfSectionReferences;
	unsigned __int64 NumberOfPfnReferences;
	unsigned __int64 NumberOfMappedViews;
	unsigned __int64 NumberOfUserReferences;
	unsigned long f1;
	unsigned long f2;
	EX_FAST_REF FilePointer;
	// Other fields
} CONTROL_AREA, *PCONTROL_AREA;

typedef struct _SUBSECTION // Size=56
{
	PCONTROL_AREA ControlArea;
	// Other fields
} SUBSECTION, *PSUBSECTION;

typedef struct _MEMORY_BASIC_INFORMATION_EX
{
	PVOID BaseAddress;
	PVOID AllocationBase;
	ULONG AllocationProtect;
	SIZE_T RegionSize;
	ULONG State;
	ULONG Protect;
	ULONG Type;
} MEMORY_BASIC_INFORMATION_EX, *PMEMORY_BASIC_INFORMATION_EX;

typedef struct _SYSTEM_CALL_COUNT_INFORMATION
{
	ULONG Length;
	ULONG NumberOfTables;
	ULONG limits[2];
} SYSTEM_CALL_COUNT_INFORMATION, *PSYSTEM_CALL_COUNT_INFORMATION;

typedef struct _SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	KWAIT_REASON WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _THREAD_BASIC_INFORMATION
{
	NTSTATUS ExitStatus;
	PVOID TebBaseAddress;
	CLIENT_ID ClientId;
	ULONG_PTR AffinityMask;
	LONG Priority;
	LONG BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
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
} SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;

#pragma warning(disable : 4214)
typedef struct _MMPTE_HARDWARE64
{
	ULONGLONG Valid : 1;
	ULONGLONG Dirty1 : 1;
	ULONGLONG Owner : 1;
	ULONGLONG WriteThrough : 1;
	ULONGLONG CacheDisable : 1;
	ULONGLONG Accessed : 1;
	ULONGLONG Dirty : 1;
	ULONGLONG LargePage : 1;
	ULONGLONG Global : 1;
	ULONGLONG CopyOnWrite : 1;
	ULONGLONG Unused : 1;
	ULONGLONG Write : 1;
	ULONGLONG PageFrameNumber : 36;
	ULONGLONG ReservedForHardware : 4;
	ULONGLONG ReservedForSoftware : 4;
	ULONGLONG WsleAge : 4;
	ULONGLONG WsleProtection : 3;
	ULONGLONG NoExecute : 1;
} MMPTE_HARDWARE64, *PMMPTE_HARDWARE64;

typedef struct _MMPTE
{
	union {
		ULONG_PTR Long;
		MMPTE_HARDWARE64 Hard;
	} u;
} MMPTE;
typedef MMPTE *PMMPTE;

#pragma warning(default : 4214)

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section; // Not filled in
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[MAXIMUM_FILENAME_LENGTH];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_SERVICE_TAG_RECORD
{
	struct _LDR_SERVICE_TAG_RECORD *Next;
	ULONG ServiceTag;
} LDR_SERVICE_TAG_RECORD, *PLDR_SERVICE_TAG_RECORD;

typedef struct _LDRP_CSLIST
{
	PSINGLE_LIST_ENTRY Tail;
} LDRP_CSLIST, *PLDRP_CSLIST;

typedef enum _LDR_DDAG_STATE {
	LdrModulesMerged = -5,
	LdrModulesInitError = -4,
	LdrModulesSnapError = -3,
	LdrModulesUnloaded = -2,
	LdrModulesUnloading = -1,
	LdrModulesPlaceHolder = 0,
	LdrModulesMapping = 1,
	LdrModulesMapped = 2,
	LdrModulesWaitingForDependencies = 3,
	LdrModulesSnapping = 4,
	LdrModulesSnapped = 5,
	LdrModulesCondensed = 6,
	LdrModulesReadyToInit = 7,
	LdrModulesInitializing = 8,
	LdrModulesReadyToRun = 9
} LDR_DDAG_STATE;

typedef struct _LDR_DDAG_NODE
{
	LIST_ENTRY Modules;
	PLDR_SERVICE_TAG_RECORD ServiceTagList;
	ULONG LoadCount;
	ULONG LoadWhileUnloadingCount;
	ULONG LowestLink;
	union {
		LDRP_CSLIST Dependencies;
		SINGLE_LIST_ENTRY RemovalLink;
	};
	LDRP_CSLIST IncomingDependencies;
	LDR_DDAG_STATE State;
	SINGLE_LIST_ENTRY CondenseLink;
	ULONG PreorderNumber;
} LDR_DDAG_NODE, *PLDR_DDAG_NODE;

typedef struct _LDR_DEPENDENCY_RECORD
{
	SINGLE_LIST_ENTRY DependencyLink;
	PLDR_DDAG_NODE DependencyNode;
	SINGLE_LIST_ENTRY IncomingDependencyLink;
	PLDR_DDAG_NODE IncomingDependencyNode;
} LDR_DEPENDENCY_RECORD, *PLDR_DEPENDENCY_RECORD;

typedef enum _LDR_DLL_LOAD_REASON {
	LoadReasonStaticDependency,
	LoadReasonStaticForwarderDependency,
	LoadReasonDynamicForwarderDependency,
	LoadReasonDelayloadDependency,
	LoadReasonDynamicLoad,
	LoadReasonAsImageLoad,
	LoadReasonAsDataLoad,
	LoadReasonUnknown = -1
} LDR_DLL_LOAD_REASON,
	*PLDR_DLL_LOAD_REASON;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	union {
		LIST_ENTRY InInitializationOrderLinks;
		LIST_ENTRY InProgressLinks;
	};
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	union {
		UCHAR FlagGroup[4];
		ULONG Flags;
		struct
		{
			ULONG PackagedBinary : 1;
			ULONG MarkedForRemoval : 1;
			ULONG ImageDll : 1;
			ULONG LoadNotificationsSent : 1;
			ULONG TelemetryEntryProcessed : 1;
			ULONG ProcessStaticImport : 1;
			ULONG InLegacyLists : 1;
			ULONG InIndexes : 1;
			ULONG ShimDll : 1;
			ULONG InExceptionTable : 1;
			ULONG ReservedFlags1 : 2;
			ULONG LoadInProgress : 1;
			ULONG LoadConfigProcessed : 1;
			ULONG EntryProcessed : 1;
			ULONG ProtectDelayLoad : 1;
			ULONG ReservedFlags3 : 2;
			ULONG DontCallForThreads : 1;
			ULONG ProcessAttachCalled : 1;
			ULONG ProcessAttachFailed : 1;
			ULONG CorDeferredValidate : 1;
			ULONG CorImage : 1;
			ULONG DontRelocate : 1;
			ULONG CorILOnly : 1;
			ULONG ReservedFlags5 : 3;
			ULONG Redirected : 1;
			ULONG ReservedFlags6 : 2;
			ULONG CompatDatabaseProcessed : 1;
		};
	};
	USHORT ObsoleteLoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
	struct _ACTIVATION_CONTEXT *EntryPointActivationContext;
	PVOID Lock;
	PLDR_DDAG_NODE DdagNode;
	LIST_ENTRY NodeModuleLink;
	struct _LDRP_LOAD_CONTEXT *LoadContext;
	PVOID ParentDllBase;
	PVOID SwitchBackContext;
	RTL_BALANCED_NODE BaseAddressIndexNode;
	RTL_BALANCED_NODE MappingInfoIndexNode;
	ULONG_PTR OriginalBase;
	LARGE_INTEGER LoadTime;
	ULONG BaseNameHashValue;
	LDR_DLL_LOAD_REASON LoadReason;
	ULONG ImplicitPathOptions;
	ULONG ReferenceCount;
	ULONG DependentLoadFlags;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA32
{
	ULONG Length;
	UCHAR Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY32 HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;

typedef struct _PEB32
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG Mutant;
	ULONG ImageBaseAddress;
	ULONG Ldr;
	ULONG ProcessParameters;
	ULONG SubSystemData;
	ULONG ProcessHeap;
	ULONG FastPebLock;
	ULONG AtlThunkSListPtr;
	ULONG IFEOKey;
	ULONG CrossProcessFlags;
	ULONG KernelCallbackTable;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	ULONG ApiSetMap;
} PEB32, *PPEB32;

typedef struct _SEP_TOKEN_PRIVILEGES
{
	ULONG64 Present;
	ULONG64 Enabled;
	ULONG64 EnabledByDefault;
} SEP_TOKEN_PRIVILEGES, * PSEP_TOKEN_PRIVILEGES;

typedef struct _SEP_AUDIT_POLICY
{
	TOKEN_AUDIT_POLICY AdtTokenPolicy;
	UCHAR PolicySetStatus;
} SEP_AUDIT_POLICY, * PSEP_AUDIT_POLICY;

typedef struct _TOKEN
{
	TOKEN_SOURCE TokenSource;
	LUID TokenId;
	LUID AuthenticationId;
	LUID ParentTokenId;
	LARGE_INTEGER ExpirationTime;
	PERESOURCE TokenLock;
	LUID ModifiedId;
	SEP_TOKEN_PRIVILEGES Privileges;
	SEP_AUDIT_POLICY AuditPolicy;
	ULONG SessionId;
	ULONG UserAndGroupCount;
	ULONG RestrictedSidCount;
	ULONG VariableLength;
	ULONG DynamicCharged;
	ULONG DynamicAvailable;
	ULONG DefaultOwnerIndex;
	PSID_AND_ATTRIBUTES UserAndGroups;
	PSID_AND_ATTRIBUTES RestrictedSids;
	PVOID PrimaryGroup;
	PULONG DynamicPart;
	PACL DefaultDacl;
	TOKEN_TYPE TokenType;
	SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
	ULONG TokenFlags;
	UCHAR TokenInUse;
	ULONG IntegrityLevelIndex;
	ULONG MandatoryPolicy;
	struct _SEP_LOGON_SESSION_REFERENCES* LogonSession;
	LUID OriginatingLogonSession;
	SID_AND_ATTRIBUTES_HASH SidHash;
	SID_AND_ATTRIBUTES_HASH RestrictedSidHash;
	struct _AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION* pSecurityAttributes;

	// Begin Windows 8/8.1/10+ only fields
	PVOID Package;
	PSID_AND_ATTRIBUTES Capabilities;
	ULONG CapabilityCount;
	SID_AND_ATTRIBUTES_HASH CapabilitiesHash;
	struct _SEP_LOWBOX_NUMBER_ENTRY* LowboxNumberEntry;
	struct _SEP_CACHED_HANDLES_ENTRY* LowboxHandlesEntry;
	struct _AUTHZBASEP_CLAIM_ATTRIBUTES_COLLECTION* pClaimAttributes;
	PVOID TrustLevelSid;
	struct _TOKEN* TrustLinkedToken;
	PVOID IntegrityLevelSidValue;
	struct _SEP_SID_VALUES_BLOCK* TokenSidValues;
	struct _SEP_LUID_TO_INDEX_MAP_ENTRY* IndexEntry;
	struct _SEP_TOKEN_DIAG_TRACK_ENTRY* DiagnosticInfo;
	struct _SEP_CACHED_HANDLES_ENTRY* BnoIsolationHandlesEntry;
	// End Windows 8/8.1/10+ only fields

	PVOID SessionObject;
	ULONG64 VariablePart;
} TOKEN, * PTOKEN;

typedef struct _WOW64_PROCESS
{
	PPEB32 Wow64;
} WOW64_PROCESS, *PWOW64_PROCESS;

typedef union _WOW64_APC_CONTEXT {
	struct
	{
		ULONG Apc32BitContext;
		ULONG Apc32BitRoutine;
	};

	PVOID Apc64BitContext;

} WOW64_APC_CONTEXT, *PWOW64_APC_CONTEXT;

#define WOW64_SIZE_OF_80387_REGISTERS		80
#define WOW64_MAXIMUM_SUPPORTED_EXTENSION	512

typedef struct _WOW64_FLOATING_SAVE_AREA
{
	ULONG	ControlWord;
	ULONG	StatusWord;
	ULONG	TagWord;
	ULONG	ErrorOffset;
	ULONG	ErrorSelector;
	ULONG	DataOffset;
	ULONG	DataSelector;
	UCHAR	RegisterArea[WOW64_SIZE_OF_80387_REGISTERS];
	ULONG	Cr0NpxState;
} WOW64_FLOATING_SAVE_AREA;

#pragma pack(push, 4)

typedef struct _WOW64_CONTEXT {
	ULONG ContextFlags;

	ULONG	Dr0;
	ULONG	Dr1;
	ULONG	Dr2;
	ULONG	Dr3;
	ULONG	Dr6;
	ULONG	Dr7;

	WOW64_FLOATING_SAVE_AREA FloatSave;

	ULONG	SegGs;
	ULONG	SegFs;
	ULONG	SegEs;
	ULONG	SegDs;

	ULONG	Edi;
	ULONG	Esi;
	ULONG	Ebx;
	ULONG	Edx;
	ULONG	Ecx;
	ULONG	Eax;

	ULONG	Ebp;
	ULONG	Eip;
	ULONG	SegCs;
	ULONG	EFlags;
	ULONG	Esp;
	ULONG	SegSs;

	UCHAR	ExtendedRegisters[WOW64_MAXIMUM_SUPPORTED_EXTENSION];
} WOW64_CONTEXT, *PWOW64_CONTEXT;

#pragma pack(pop)

typedef struct _KLDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	ULONG ExceptionTableSize;
	// ULONG padding on IA64
	PVOID GpValue;
	PNON_PAGED_DEBUG_INFO NonPagedDebugInfo;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT __Unused5;
	PVOID SectionPointer;
	ULONG CheckSum;
	// ULONG padding on IA64
	PVOID LoadedImports;
	PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;
