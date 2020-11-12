#pragma once

#if defined(__INTELLISENSE__) || defined(__RESHARPER__) || defined(__clang__)
#define _KERNEL_MODE 1
#if (defined(_WIN64) || defined(_AMD64_) || defined(AMD64)) && (!defined(_M_AMD64))
#define _M_AMD64 1
#endif
#endif

#include <intrin.h>
#include <ntifs.h>
#include "zwapi.h"
#include "BlackBone/Private.h"
#include <ntimage.h>

#if ((NTDDI_VERSION >= NTDDI_WIN8 && defined(_M_AMD64) && defined(NT_INLINE_IRQL)) && \
	!defined(NTDDI_WIN10_RS5))
	#error You need to update your WDK installation so that NT_INLINE_IRQL will work
#endif

#if !defined(NTDDI_WIN10_19H1)
	#define NTDDI_WIN10_19H1 (NTDDI_WIN10_RS5 + 1)
#endif

#if OBFUSCATE
#include "VMProtectDDK.h"
#else
#include "VMProtectStub.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__INTELLISENSE__) && defined(NT_ASSERT_ACTION)
	#undef NT_ASSERT_ACTION
	#undef NT_ASSERTMSG_ASSUME
	#undef NT_ASSERTMSGW_ASSUME
	#define NT_ASSERT_ACTION(exp)			(NT_ANALYSIS_ASSUME(exp), 0)
	#define NT_ASSERTMSG_ASSUME(msg, exp)	(NT_ANALYSIS_ASSUME(exp), 0)
	#define NT_ASSERTMSGW_ASSUME(msg, exp)	(NT_ANALYSIS_ASSUME(exp), 0)
#elif defined(__clang__)
	#ifdef PAGED_CODE
		#undef PAGED_CODE
		#define PAGED_CODE()				((void)0)
	#endif
	#ifdef ALLOC_PRAGMA
		
		#undef ALLOC_PRAGMA
		#undef ALLOC_DATA_PRAGMA
	#endif

	#pragma clang diagnostic ignored "-Wunknown-pragmas"
	#pragma clang diagnostic ignored "-Wmissing-field-initializers"
#endif
#if defined(__RESHARPER__)
	#undef DECLSPEC_IMPORT
	#define DECLSPEC_IMPORT extern
#endif

#ifdef __cplusplus
#define CONSTEXPR constexpr
#else
#define CONSTEXPR
#endif

#if defined(__RESHARPER__) || defined(__GNUC__)
#define PRINTF_ATTR(FormatIndex, FirstToCheck) \
	[[gnu::format(printf, FormatIndex, FirstToCheck)]]
#else
#define PRINTF_ATTR(FormatIndex, FirstToCheck)
#endif

#if defined(__RESHARPER__)
#define WPRINTF_ATTR(FormatIndex, FirstToCheck) \
	[[rscpp::format(wprintf, FormatIndex, FirstToCheck)]]
#else
#define WPRINTF_ATTR(FormatIndex, FirstToCheck)
#endif

#define IMAGE32(NtHeaders) ((NtHeaders)->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
#define IMAGE64(NtHeaders) ((NtHeaders)->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)

#define HEADER_FIELD(NtHeaders, Field) (IMAGE64(NtHeaders) \
	? ((PIMAGE_NT_HEADERS64)(NtHeaders))->OptionalHeader.Field \
	: ((PIMAGE_NT_HEADERS32)(NtHeaders))->OptionalHeader.Field)
#define THUNK_VAL(NtHeaders, Ptr, Val) (IMAGE64(NtHeaders) \
	? ((PIMAGE_THUNK_DATA64)(Ptr))->Val \
	: ((PIMAGE_THUNK_DATA32)(Ptr))->Val)

#define ALIGN_TO_SECTIONS(Size, SectionAlign)	(((ULONG)(Size) + (SectionAlign) - 1) & ~((SectionAlign) - 1))

#ifndef ExFreePool
#define ExFreePool(P) ExFreePoolWithTag(P, 0UL)
#endif
#define ObfDereferenceObject(Object) ObfDereferenceObjectWithTag(Object, 'tlfD')

NTSYSAPI
ULONG
NtBuildNumber;

FORCEINLINE
PKTHREAD
KiGetCurrentThread(
	)
{
#ifdef _M_IX86
	return reinterpret_cast<PKTHREAD>(static_cast<ULONG_PTR>(__readfsdword(0x124)));
#else
	return reinterpret_cast<PKTHREAD>(static_cast<ULONG_PTR>(__readgsqword(0x188)));
#endif
}

CONSTEXPR
FORCEINLINE
LONGLONG
RtlMsToTicks(
	_In_ ULONG Milliseconds
	)
{
	return 10000LL * static_cast<LONGLONG>(Milliseconds);
}

FORCEINLINE
VOID
RtlSleep(
	_In_ ULONG Milliseconds
	)
{
	LARGE_INTEGER Timeout;
	Timeout.QuadPart = -1 * RtlMsToTicks(Milliseconds);
	KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
}

CONSTEXPR
FORCEINLINE
BOOLEAN
IsWin64(
	)
{
#if defined(_WIN64) || defined(_M_AMD64)
	return TRUE;
#else
	return FALSE;
#endif
}

CONSTEXPR
FORCEINLINE
BOOLEAN
RtlIsCanonicalAddress(
	ULONG_PTR Address
	)
{
#if !defined(_WIN64) && !defined(_M_AMD64)
	UNREFERENCED_PARAMETER(Address);
	return true;
#else

	return (((Address & 0xFFFF800000000000) + 0x800000000000) & ~0x800000000000) == 0;
#endif
}

typedef
NTSTATUS
(NTAPI*
t_NtCreateThreadEx)(
	_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ HANDLE ProcessHandle,
	_In_ PUSER_THREAD_START_ROUTINE StartRoutine,
	_In_opt_ PVOID Argument,
	_In_ ULONG CreateFlags,
	_In_opt_ ULONG_PTR ZeroBits,
	_In_opt_ SIZE_T StackSize,
	_In_opt_ SIZE_T MaximumStackSize,
	_In_opt_ PPS_ATTRIBUTE_LIST AttributeList
	);

typedef
NTSTATUS
(NTAPI*
t_NtResumeThread)(
	_In_ HANDLE ThreadHandle,
	_Out_opt_ PULONG PreviousSuspendCount
	);

typedef
NTSTATUS
(NTAPI*
t_NtTerminateThread)(
	_In_opt_ HANDLE ThreadHandle,
	_In_ NTSTATUS ExitStatus
	);

typedef
NTSTATUS
(NTAPI*
t_NtProtectVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID *BaseAddress,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG NewProtect,
	_Out_ PULONG OldProtect
	);

#if !OBFUSCATE
PRINTF_ATTR(1, 2)
VOID
Printf(
	_In_ PCCH Format,
	_In_ ...
	);
#else
#define Printf(...) NT_ANALYSIS_ASSUME(__VA_ARGS__)
#endif

_Function_class_(DRIVER_INITIALIZE)
_IRQL_requires_(PASSIVE_LEVEL)
DRIVER_INITIALIZE
DriverEntry;

_Function_class_(DRIVER_UNLOAD)
_IRQL_requires_(PASSIVE_LEVEL)
DRIVER_UNLOAD
DriverUnload;

_Function_class_(IO_WORKITEM_ROUTINE_EX)
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
IO_WORKITEM_ROUTINE_EX
InjectDllWorker;

_Function_class_(IO_WORKITEM_ROUTINE_EX)
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
IO_WORKITEM_ROUTINE_EX
CleanMmUnloadedDriversWorker;

NTSTATUS
StartDllThread(
	_In_ PVOID ImageBase,
	_In_ ULONG EntryPointRva,
	_In_ BOOLEAN IsWow64
	);

NTSTATUS
InjectDll(
	_In_opt_ ULONG ProcessId,
	_In_opt_ PUNICODE_STRING ProcessName,
	_In_opt_ BOOLEAN WaitForNamedProcess,
	_In_ PUNICODE_STRING DllNtPath,
	_In_ BOOLEAN DeleteDll,
	_In_ BOOLEAN WipeImageHeaders
	);

PIMAGE_NT_HEADERS
NTAPI
RtlpImageNtHeaderEx(
	_In_ PVOID Base,
	_In_opt_ SIZE_T Size
	);

PVOID
GetProcedureAddress(
	_In_ ULONG_PTR DllBase,
	_In_ PCSTR RoutineName
	);

PVOID
GetFileDataProcedureAddress(
	_In_ ULONG_PTR FileData,
	_In_ PCSTR RoutineName
	);

ULONG
RvaToOffset(
	_In_ PIMAGE_NT_HEADERS NtHeaders,
	_In_ ULONG Rva
	);

PVOID
NTAPI
RtlpImageDirectoryEntryToDataEx(
	_In_ PVOID Base,
	_In_ BOOLEAN MappedAsImage,
	_In_ USHORT DirectoryEntry,
	_Out_ PULONG Size
	);

#ifdef __cplusplus
extern "C++"
CONSTEXPR
#endif
ULONG
CharacteristicsToPageProtection(
	_In_ ULONG SectionCharacteristics
	);

#ifdef __cplusplus
extern "C++"
CONSTEXPR
#endif
BOOLEAN
IsVadProtectionChangeAllowed(
	_In_ PMMVAD_SHORT VadShort
	);

#if NTDDI_VERSION >= NTDDI_WIN10

#ifdef __cplusplus
extern "C++"
CONSTEXPR
#endif
BOOLEAN
IsVadProtectionChangeAllowed19H1(
	_In_ PMMVAD_SHORT_19H1 VadShort
	);

#endif

NTSTATUS
LdrRelocateImageData(
	_In_ PVOID FileData,
	_In_ PVOID NewBase
	);

NTSTATUS
PatchGuardCFCheckFunctionPointers(
	_In_ PEPROCESS Process
	);

VOID
InitializeStackCookie(
	_In_ PVOID ImageBase,
	_In_ PCLIENT_ID ClientId
	);

PVOID
RandomiseImageBase(
	_In_ PIMAGE_NT_HEADERS NtHeaders,
	_In_opt_ PVOID PreferredBase
	);

PVOID
RandomiseSystemImageBase(
	_In_ PEPROCESS Process,
	_In_ PIMAGE_NT_HEADERS NtHeaders
	);

NTSTATUS
ResolveImports(
	_In_ PEPROCESS Process,
	_In_ PVOID ImageBase,
	_In_ BOOLEAN WipeNames
	);

VOID
WipeImageSections(
	_In_ PVOID ImageBase,
	_In_ BOOLEAN PhysicalAllocation,
	_In_ PIMAGE_SECTION_HEADER SectionHeaders,
	_In_ BOOLEAN WipeHeaders
	);

NTSTATUS
NTAPI
IopGetFileSize(
	_In_ PFILE_OBJECT FileObject,
	_Inout_ PLARGE_INTEGER FileSize
	);

NTSTATUS
NTAPI
IopReadFile(
	_In_ PFILE_OBJECT FileObject,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_Out_ PVOID Buffer,
	_In_ ULONG Length,
	_In_ PLARGE_INTEGER ByteOffset
	);

PDEVICE_OBJECT
IopGetBaseFsDeviceObject(
	_In_ PUNICODE_STRING FileName
	);

NTSTATUS
RtlReadFileToBytes(
	_In_ PUNICODE_STRING NtPath,
	_Out_ PUCHAR *Buffer,
	_Out_opt_ PSIZE_T FileSize
	);

VOID
CreateProcessNotifyRoutine(
	_Inout_ PEPROCESS Process,
	_In_ HANDLE ProcessId,
	_Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
	);

NTSTATUS
OpenSessionProcess(
	_Out_ PEPROCESS *Process,
	_In_ PUNICODE_STRING ProcessName,
	_In_ ULONG SessionId,
	_In_ BOOLEAN Wait
	);

VOID
CancelAllProcessWaits(
	);

KPROCESSOR_MODE
KeSetPreviousMode(
	_In_ KPROCESSOR_MODE ProcessorMode
	);

PVOID
GetSyscallAddress(
	_In_ PCSTR FunctionName
	);

NTSTATUS
SsdtInitialize(
	);

VOID
SsdtUninitialize(
	);

NTSTATUS
LocatePageTables(
	_Inout_ PDYNAMIC_DATA Data
	);

NTSTATUS
LocatePspNotifyEnableMask(
	_Inout_ PDYNAMIC_DATA Data
	);

NTSTATUS
LocateMmUnloadedDrivers(
	_Inout_ PDYNAMIC_DATA Data
	);

NTSTATUS
LocatePiDDBCacheTable(
	_Inout_ PDYNAMIC_DATA Data
	);

NTSTATUS
DecryptPeFile(
	_In_ PUCHAR EncryptedDllBuffer,
	_In_ SIZE_T EncryptedDllSize,
	_Out_ PUCHAR *DecryptedDllBuffer,
	_Out_ PSIZE_T DecryptedDllSize,
	_Out_ PIMAGE_NT_HEADERS *NtHeaders
	);

#ifdef __cplusplus
}
#endif
