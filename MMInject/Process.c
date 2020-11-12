#include "MMInject.h"
#include "Utils.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, CreateProcessNotifyRoutine)
#pragma alloc_text(PAGE, OpenSessionProcess)
#pragma alloc_text(PAGE, CancelAllProcessWaits)
#endif

static KEVENT ProcessCreatedEvent;
static PUNICODE_STRING NotifyProcessName = nullptr;
static PEPROCESS NotifyProcess = nullptr;

VOID
CreateProcessNotifyRoutine(
	_Inout_ PEPROCESS Process,
	_In_ HANDLE ProcessId,
	_Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
	)
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(ProcessId);

	if (CreateInfo == nullptr || CreateInfo->ImageFileName == nullptr ||
		!RtlUnicodeStringEndsIn(CreateInfo->ImageFileName, NotifyProcessName))
		return;

	ObfReferenceObjectWithTag(Process, GetPoolTag());
	NotifyProcess = Process;
	KeSetEvent(&ProcessCreatedEvent,
				IO_NO_INCREMENT,
				FALSE);
}

NTSTATUS
OpenSessionProcess(
	_Out_ PEPROCESS *Process,
	_In_ PUNICODE_STRING ProcessName,
	_In_ ULONG SessionId,
	_In_ BOOLEAN Wait
	)
{
	PAGED_CODE();

	ULONG Size;
	if (NtQuerySystemInformation(SystemProcessInformation, nullptr, 0, &Size) != STATUS_INFO_LENGTH_MISMATCH)
		return STATUS_UNSUCCESSFUL;
	const PSYSTEM_PROCESS_INFORMATION SystemProcessInfo =
		static_cast<PSYSTEM_PROCESS_INFORMATION>(ExAllocatePoolWithTag(NonPagedPoolNx, 2 * Size, GetPoolTag()));
	if (SystemProcessInfo == nullptr)
		return STATUS_NO_MEMORY;
	NTSTATUS Status = NtQuerySystemInformation(SystemProcessInformation,
												SystemProcessInfo,
												2 * Size,
												nullptr);
	if (!NT_SUCCESS(Status))
	{
		ExFreePool(SystemProcessInfo);
		return Status;
	}

	PSYSTEM_PROCESS_INFORMATION Entry = SystemProcessInfo;
	Status = STATUS_NOT_FOUND;

	while (true)
	{
		if (Entry->ImageName.Buffer != nullptr &&
			RtlCompareUnicodeString(&Entry->ImageName, ProcessName, TRUE) == 0)
		{
			Status = PsLookupProcessByProcessId(Entry->UniqueProcessId, Process);
			if (NT_SUCCESS(Status))
			{
				if (PsGetProcessSessionIdEx(*Process) == SessionId)
					break;
				
				ObfDereferenceObject(*Process);
			}
		}

		if (Entry->NextEntryOffset == 0)
			break;

		Entry = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<ULONG_PTR>(Entry) +
																Entry->NextEntryOffset);
	}
	ExFreePool(SystemProcessInfo);

	if (Status == STATUS_NOT_FOUND && Wait)
	{
		Printf("Waiting for process %wZ...\n", ProcessName);
		NotifyProcessName = ProcessName;
		NotifyProcess = nullptr;

		KeInitializeEvent(&ProcessCreatedEvent,
						NotificationEvent,
						FALSE);

		PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, FALSE);

		KeWaitForSingleObject(&ProcessCreatedEvent,
							Executive,
							KernelMode,
							FALSE,
							nullptr);

		PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, TRUE);

		if (NotifyProcess == nullptr)
		{
			Status = STATUS_CANCELLED;
			*Process = nullptr;
		}
		else
		{
			Status = STATUS_SUCCESS;
			*Process = NotifyProcess;

			RtlSleep(50);
		}
	}

	NotifyProcessName = nullptr;
	NotifyProcess = nullptr;

	return Status;
}

VOID
CancelAllProcessWaits(
	)
{
	PAGED_CODE();

	if (NotifyProcessName == nullptr)
	{
		return;
	}

	NotifyProcess = nullptr;
	KeSetEvent(&ProcessCreatedEvent,
				IO_NO_INCREMENT,
				FALSE);
}
