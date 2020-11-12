#include "MMInject.h"
#include "Utils.h"

extern "C"
_Function_class_(IO_COMPLETION_ROUTINE)
_IRQL_requires_same_
_IRQL_requires_max_(DISPATCH_LEVEL)
IO_COMPLETION_ROUTINE
IoCompletionRoutine;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, IopGetFileSize)
#pragma alloc_text(PAGE, IopReadFile)
#pragma alloc_text(PAGE, IopGetBaseFsDeviceObject)
#pragma alloc_text(PAGE, RtlReadFileToBytes)
#endif

_IRQL_requires_max_(DISPATCH_LEVEL)
FORCEINLINE
VOID
IopSetCompletionRoutine(
	_In_ PIRP Irp,
	_In_ PIO_COMPLETION_ROUTINE CompletionRoutine
	)
{
	const PIO_STACK_LOCATION IrpStackPointer = Irp->Tail.Overlay.CurrentStackLocation - 1;
	IrpStackPointer->CompletionRoutine = CompletionRoutine;
	IrpStackPointer->Context = IrpStackPointer->FileObject;
	IrpStackPointer->Control = (SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL);
}

_Use_decl_annotations_
NTSTATUS
IoCompletionRoutine(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp,
	_In_reads_opt_(_Inexpressible_("varies")) PVOID Context
	)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	PFILE_OBJECT FileObject = static_cast<PFILE_OBJECT>(Context);
	NT_ASSERT(FileObject != nullptr);

	if (Irp->PendingReturned)
	{
		Irp->Tail.Overlay.CurrentStackLocation->Control |= SL_PENDING_RETURNED;
	}

	FileObject->FinalStatus = !NT_ERROR(Irp->IoStatus.Status) ? STATUS_SUCCESS : Irp->IoStatus.Status;
	KeSetEvent(&FileObject->Event, EVENT_INCREMENT, FALSE);

	IoFreeIrp(Irp);

	return STATUS_MORE_PROCESSING_REQUIRED;
}

FORCEINLINE
VOID
IopAcquireFileObjectLock(
	_In_ PFILE_OBJECT FileObject
	)
{
	
	while (_InterlockedExchange(reinterpret_cast<PLONG>(&FileObject->Busy),
		static_cast<ULONG>(TRUE)) != FALSE)
	{
		_mm_pause();
	}
	ObfReferenceObjectWithTag(FileObject, GetPoolTag());
}

FORCEINLINE
VOID
IopReleaseFileObjectLock(
	_In_ PFILE_OBJECT FileObject
	)
{
	_InterlockedExchange(reinterpret_cast<PLONG>(&FileObject->Busy), FALSE);
	if (FileObject->Waiters != 0)
		KeSetEvent(&FileObject->Lock, 0, FALSE);
	ObfDereferenceObject(FileObject);
}

FORCEINLINE
NTSTATUS
IopCallDriver(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
	)
{
	Irp->CurrentLocation--;

	const PIO_STACK_LOCATION IrpStackPointer = Irp->Tail.Overlay.CurrentStackLocation - 1;
	Irp->Tail.Overlay.CurrentStackLocation = IrpStackPointer;
	IrpStackPointer->DeviceObject = DeviceObject;

	return DeviceObject->DriverObject->MajorFunction[IrpStackPointer->MajorFunction](DeviceObject, Irp);
}

NTSTATUS
NTAPI
IopGetFileSize(
	_In_ PFILE_OBJECT FileObject,
	_Inout_ PLARGE_INTEGER FileSize
	)
{
	PAGED_CODE();

	const PDEVICE_OBJECT DeviceObject = IoGetBaseFileSystemDeviceObject(FileObject);
	const PIRP Irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);

	KEVENT Event;
	KeInitializeEvent(&Event, NotificationEvent, FALSE);

	IO_STATUS_BLOCK IoStatusBlock;
	FILE_STANDARD_INFORMATION FileInformation;
	Irp->Flags = IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO;
	Irp->RequestorMode = KernelMode;
	Irp->UserIosb = &IoStatusBlock;
	Irp->UserEvent = &Event;
	Irp->Tail.Overlay.OriginalFileObject = FileObject;
	Irp->Tail.Overlay.Thread = KiGetCurrentThread();
	Irp->AssociatedIrp.SystemBuffer = &FileInformation;

	NT_ASSERT(Irp->CurrentLocation > 0);
	PIO_STACK_LOCATION IrpStackPointer = Irp->Tail.Overlay.CurrentStackLocation - 1;
	IrpStackPointer->MajorFunction = IRP_MJ_QUERY_INFORMATION;
	IrpStackPointer->FileObject = FileObject;
	IrpStackPointer->DeviceObject = DeviceObject;
	IrpStackPointer->Parameters.SetFile.Length = sizeof(FILE_STANDARD_INFORMATION);
	IrpStackPointer->Parameters.SetFile.FileInformationClass = FileStandardInformation;

	const NTSTATUS Status = IopCallDriver(DeviceObject, Irp);

	if (Status == STATUS_PENDING)
	{
		KeWaitForSingleObject(&Event,
							Executive,
							KernelMode,
							FALSE,
							nullptr);
	}

	if (!NT_SUCCESS(Status))
		IoStatusBlock.Status = Status;

	NT_ASSERT(!FileInformation.Directory || !NT_SUCCESS(IoStatusBlock.Status));
	*FileSize = FileInformation.EndOfFile;

	return IoStatusBlock.Status;
}

NTSTATUS
NTAPI
IopReadFile(
	_In_ PFILE_OBJECT FileObject,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_Out_ PVOID Buffer,
	_In_ ULONG Length,
	_In_ PLARGE_INTEGER ByteOffset
	)
{
	PAGED_CODE();

	const PDEVICE_OBJECT DeviceObject = IoGetBaseFileSystemDeviceObject(FileObject);
	if (DeviceObject->Flags & DO_BUFFERED_IO ||
		DeviceObject->Flags & DO_DIRECT_IO)
		return STATUS_NOT_SUPPORTED;
	if (!(FileObject->Flags & FO_SYNCHRONOUS_IO))
		return STATUS_NOT_SUPPORTED;

	constexpr ULONG FileObjectFlags = FO_SYNCHRONOUS_IO;
	FileObject->Flags |= FileObjectFlags;

	if constexpr ((FileObjectFlags & FO_SYNCHRONOUS_IO) != 0)
		IopAcquireFileObjectLock(FileObject);

	KeClearEvent(&FileObject->Event);

	const PIRP Irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);

	Irp->Tail.Overlay.OriginalFileObject = FileObject;
	Irp->Tail.Overlay.Thread = KiGetCurrentThread();
	Irp->Tail.Overlay.AuxiliaryBuffer = nullptr;
	Irp->RequestorMode = KernelMode;
	Irp->PendingReturned = FALSE;
	Irp->Cancel = FALSE;
	Irp->CancelRoutine = nullptr;
	Irp->UserEvent = nullptr;
	Irp->UserIosb = IoStatusBlock;
	Irp->Overlay.AsynchronousParameters.UserApcRoutine = nullptr;
	Irp->Overlay.AsynchronousParameters.UserApcContext = nullptr;

	NT_ASSERT(Irp->CurrentLocation > 0);
	PIO_STACK_LOCATION IrpStackPointer = Irp->Tail.Overlay.CurrentStackLocation - 1;
	*reinterpret_cast<PULONG>(&IrpStackPointer->MajorFunction) = IRP_MJ_READ;
	IrpStackPointer->FileObject = FileObject;

	IopSetCompletionRoutine(Irp, IoCompletionRoutine);
	Irp->AssociatedIrp.SystemBuffer = nullptr;
	Irp->MdlAddress = nullptr;
	Irp->UserBuffer = Buffer;
	constexpr ULONG IrpFlags = IRP_READ_OPERATION | IRP_DEFER_IO_COMPLETION;
	Irp->Flags = IrpFlags;

	IrpStackPointer->Parameters.Read.Length = Length;
	IrpStackPointer->Parameters.Read.Key = 0;
	IrpStackPointer->Parameters.Read.ByteOffset = *ByteOffset;

	NTSTATUS Status = IopCallDriver(DeviceObject, Irp);

	if constexpr ((IrpFlags & IRP_DEFER_IO_COMPLETION) != 0)
	{
		if (Status != STATUS_PENDING)
		{
			NT_ASSERT(FileObject->Event.Header.SignalState != 0);
		}
	}

	if constexpr ((FileObjectFlags & FO_SYNCHRONOUS_IO) != 0)
	{
		if (Status == STATUS_PENDING)
		{
			
			KeWaitForSingleObject(&FileObject->Event,
									Executive,
									KernelMode,
									static_cast<BOOLEAN>((FileObject->Flags & FO_ALERTABLE_IO) != 0),
									nullptr);
		}

		IopReleaseFileObjectLock(FileObject);
	}

	Status = FileObject->FinalStatus;

	return Status;
}

PDEVICE_OBJECT
IopGetBaseFsDeviceObject(
	_In_ PUNICODE_STRING FileName
	)

{
	PAGED_CODE();

	UNICODE_STRING Directory;
	NTSTATUS Status = RtlStripFilename(FileName, &Directory);
	if (!NT_SUCCESS(Status))
		return nullptr;

	OBJECT_ATTRIBUTES ObjectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(&Directory, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE);
	IO_STATUS_BLOCK IoStatusBlock;
	HANDLE FileHandle;
	Status = IoCreateFileEx(&FileHandle,
							FILE_GENERIC_READ,
							&ObjectAttributes,
							&IoStatusBlock,
							nullptr,
							FILE_ATTRIBUTE_DIRECTORY,
							FILE_SHARE_READ | FILE_SHARE_DELETE,
							FILE_OPEN,
							FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT | FILE_OPEN_FOR_BACKUP_INTENT,
							nullptr,
							0,
							CreateFileTypeNone,
							nullptr,
							IO_NO_PARAMETER_CHECKING | IO_IGNORE_SHARE_ACCESS_CHECK,
							nullptr);
	if (!NT_SUCCESS(Status))
		return nullptr;

	PFILE_OBJECT FileObject = nullptr;
	Status = ObReferenceObjectByHandleWithTag(FileHandle,
											FILE_GENERIC_READ,
											*IoFileObjectType,
											KernelMode,
											GetPoolTag(),
											reinterpret_cast<PVOID*>(&FileObject),
											nullptr);
	if (!NT_SUCCESS(Status))
	{
		ObCloseHandle(FileHandle, KernelMode);
		return nullptr;
	}

	
	const PDEVICE_OBJECT DeviceObject = IoGetRelatedDeviceObject(FileObject);
	PDEVICE_OBJECT BaseFsDeviceObject = DeviceObject;
	if (DeviceObject != nullptr)
	{
		BaseFsDeviceObject = IoGetDeviceAttachmentBaseRef(DeviceObject);
	}

	ObfDereferenceObject(FileObject);
	ObCloseHandle(FileHandle, KernelMode);

	return BaseFsDeviceObject;
}

NTSTATUS
RtlReadFileToBytes(
	_In_ PUNICODE_STRING NtPath,
	_Out_ PUCHAR *Buffer,
	_Out_opt_ PSIZE_T FileSize
	)
{
	PAGED_CODE();

	IO_DRIVER_CREATE_CONTEXT DriverCreateContext;
	IoInitializeDriverCreateContext(&DriverCreateContext);
	const PDEVICE_OBJECT BaseFsDeviceObject = IopGetBaseFsDeviceObject(NtPath);
	DriverCreateContext.DeviceObjectHint = BaseFsDeviceObject;

#ifdef _DEBUG
	Printf("Opening file \"%wZ\"... [bypassing FS minifilter drivers: %hs]\n", NtPath, BaseFsDeviceObject != nullptr ? "yes" : "no");
#endif
	OBJECT_ATTRIBUTES ObjectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(NtPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE);
	IO_STATUS_BLOCK IoStatusBlock;
	HANDLE FileHandle = nullptr;
	PFILE_OBJECT FileObject = nullptr;

	NTSTATUS Status = IoCreateFileEx(&FileHandle,
									FILE_GENERIC_READ,
									&ObjectAttributes,
									&IoStatusBlock,
									nullptr,
									FILE_ATTRIBUTE_NORMAL,
									FILE_SHARE_READ | FILE_SHARE_DELETE,
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
	if (!NT_SUCCESS(Status))
	{
		Printf("IoCreateFileEx: %08X\n", Status);
		goto finished;
	}
	
	Status = ObReferenceObjectByHandleWithTag(FileHandle,
											FILE_GENERIC_READ,
											*IoFileObjectType,
											KernelMode,
											GetPoolTag(),
											reinterpret_cast<PVOID*>(&FileObject),
											nullptr);
	if (!NT_SUCCESS(Status))
		goto finished;

	LARGE_INTEGER SizeOnDisk;
	Status = IopGetFileSize(FileObject, &SizeOnDisk);
	if (!NT_SUCCESS(Status))
		goto finished;
	
	*Buffer = static_cast<PUCHAR>(ExAllocatePoolWithTag(NonPagedPoolNx, static_cast<SIZE_T>(SizeOnDisk.QuadPart), GetPoolTag()));
	if (*Buffer == nullptr)
	{
		Status = STATUS_NO_MEMORY;
		goto finished;
	}
	
	LARGE_INTEGER Offset;
	Offset.QuadPart = 0;
	Status = IopReadFile(FileObject,
						&IoStatusBlock,
						*Buffer,
						SizeOnDisk.LowPart,
						&Offset);

	if (FileSize != nullptr)
		*FileSize = static_cast<SIZE_T>(SizeOnDisk.QuadPart);

finished:
	if (FileObject != nullptr)
		ObfDereferenceObject(FileObject);
	if (FileHandle != nullptr)
		ObCloseHandle(FileHandle, KernelMode);
	if (BaseFsDeviceObject != nullptr)
		ObfDereferenceObject(BaseFsDeviceObject);

	return Status;
}
