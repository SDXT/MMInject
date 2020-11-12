#include "MMInject.h"
#include "Utils.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, RtlAdjustProcessPrivilege)
#pragma alloc_text(PAGE, RegQueryValueString)
#pragma alloc_text(PAGE, RegQueryValueBoolean)
#pragma alloc_text(PAGE, RtlUnicodeStringEndsIn)
#pragma alloc_text(PAGE, RtlStripPath)
#pragma alloc_text(PAGE, RtlStripFilename)
#pragma alloc_text(PAGE, RtlFileExists)
#endif

#define RANDOM_SEED_INIT 0x3AF84E05
static ULONG RandomSeed = RANDOM_SEED_INIT;

ULONG
RtlNextRandom(
	_In_ ULONG Min,
	_In_ ULONG Max
	)
{
	if (RandomSeed == RANDOM_SEED_INIT)
		RandomSeed = static_cast<ULONG>(__rdtsc());

	const ULONG Scale = static_cast<ULONG>(MAXINT32) / (Max - Min);
	return RtlRandomEx(&RandomSeed) / Scale + Min;
}

static
FORCEINLINE
ULONG64
XorShift64(
	_Inout_ PULONG64 State
	)
{
	ULONG64 Val = *State;
	Val ^= Val << 13;
	Val ^= Val >> 7;
	Val ^= Val << 17;
	*State = Val;
	return Val;
}

VOID
RtlFillGarbageMemory(
	_In_ PVOID Destination,
	_In_ SIZE_T Size
	)
{
	ULONG64 State = __rdtsc();

	SIZE_T AlignedSize = (Size + sizeof(ULONG64) - 1) & ~(sizeof(ULONG64) - 1);
	if (AlignedSize > Size)
	{
		const PUCHAR NewDestination = static_cast<PUCHAR>(Destination) + sizeof(ULONG64) - (AlignedSize - Size);
		const SIZE_T Skip = NewDestination - static_cast<PUCHAR>(Destination);
		for (SIZE_T i = 0; i < Skip; ++i)
		{
			*(static_cast<PUCHAR>(Destination) + i) = reinterpret_cast<PUCHAR>(&State)[i];
		}
		Destination = NewDestination;
		AlignedSize -= sizeof(ULONG64);
	}

	for (SIZE_T i = 0; i < AlignedSize / sizeof(ULONG64); ++i)
	{
		static_cast<PULONG64>(Destination)[i] = XorShift64(&State);
	}
}

ULONG
GetPoolTag(
	)
{
	CONSTEXPR const ULONG PoolTags[] =
	{
		' prI',
		'+prI',
		'eliF',
		'atuM',
		'sFtN',
		'ameS',
		'RwtE',
		'nevE',
		' daV',
		'sdaV',
		'aCmM',
		'  oI',
		'tiaW',
		'eSmM',
		'CPLA',
		'GwtE',
		' ldM',
		'erhT',
		'cScC',
		'KgxD',
	};

	CONSTEXPR const ULONG NumPoolTags = ARRAYSIZE(PoolTags);
	const ULONG Index = RtlNextRandom(0, NumPoolTags);
	NT_ASSERT(Index <= NumPoolTags - 1);
	return PoolTags[Index];
}

NTSTATUS
RtlFuckingCopyMemory(
	_In_ PVOID Destination,
	_In_ CONST VOID* Source,
	_In_ ULONG Length
	)
{
	NTSTATUS Status;
	CSHORT OriginalMdlFlags = 0;
	PVOID Mapped = nullptr;

	const KIRQL Kirql = KeRaiseIrqlToDpcLevel();
	const SIZE_T MdlSize = sizeof(MDL) + sizeof(PFN_NUMBER) * ADDRESS_AND_SIZE_TO_SPAN_PAGES(Destination, Length);
#pragma prefast(push)
#pragma prefast(disable:__WARNING_MEMORY_LEAK, "False positive - IoFreeMdl frees this memory")
	PMDL Mdl = static_cast<PMDL>(ExAllocatePoolWithTag(NonPagedPoolNx, MdlSize, GetPoolTag()));
#pragma prefast(pop)
	if (Mdl == nullptr)
	{
		Status = STATUS_NO_MEMORY;
		goto finished;
	}
	RtlZeroMemory(Mdl, MdlSize);
	MmInitializeMdl(Mdl, Destination, Length);

#pragma prefast(push)
#pragma prefast(disable:__WARNING_MODIFYING_MDL, "Trust me, I'm a scientist")
	Mdl->MdlFlags |= MDL_IO_SPACE;
	MmBuildMdlForNonPagedPool(Mdl);
	Mdl->MdlFlags &= ~MDL_IO_SPACE;

	OriginalMdlFlags = Mdl->MdlFlags;
	Mdl->MdlFlags |= MDL_PAGES_LOCKED;
	Mdl->MdlFlags &= ~MDL_SOURCE_IS_NONPAGED_POOL;

	Mapped = MmMapLockedPagesSpecifyCache(Mdl,
										KernelMode,
										MmCached,
										nullptr,
										FALSE,
										HighPagePriority | MdlMappingNoExecute);
	if (Mapped == nullptr)
	{
		Status = STATUS_NONE_MAPPED;
		goto finished;
	}

	RtlCopyMemory(Mapped, Source, Length);
	Status = STATUS_SUCCESS;

finished:
	if (Mapped != nullptr)
		MmUnmapLockedPages(Mapped, Mdl);
	if (Mdl != nullptr)
	{
		Mdl->MdlFlags = OriginalMdlFlags;
		IoFreeMdl(Mdl);
	}
#pragma prefast(pop)

	KeLowerIrql(Kirql);

	return Status;
}

NTSTATUS
RtlAdjustProcessPrivilege(
	_In_ PEPROCESS Process,
	_In_ ULONG Privilege,
	_In_ BOOLEAN Enable
	)
{
	PAGED_CODE();

	const ULONG64 QuadPrivilege = (1ULL << static_cast<ULONG64>(Privilege));

	PTOKEN Token = static_cast<PTOKEN>(PsReferencePrimaryToken(Process));

	ExAcquireResourceExclusiveLite(Token->TokenLock, TRUE);

	PSEP_TOKEN_PRIVILEGES TokenPrivileges = &Token->Privileges;
	TokenPrivileges->Present |= QuadPrivilege;
	if ((TokenPrivileges->EnabledByDefault & QuadPrivilege) == 0)
	{
		if (Enable)
		{
			TokenPrivileges->Enabled |= QuadPrivilege;
		}
		else
		{
			TokenPrivileges->Enabled &= ~QuadPrivilege;
		}
	}

	ExReleaseResourceLite(Token->TokenLock);

	PsDereferencePrimaryToken(Token);

	return STATUS_SUCCESS;
}

NTSTATUS
RegQueryValueString(
	_In_ PWSTR KeyNameBuffer,
	_In_ PWSTR ValueNameBuffer,
	_Inout_ PUNICODE_STRING ValueString
	)
{
	PAGED_CODE();

	UNICODE_STRING KeyName, ValueName;
	RtlxInitUnicodeString(&KeyName, KeyNameBuffer);
	RtlxInitUnicodeString(&ValueName, ValueNameBuffer);
	OBJECT_ATTRIBUTES ObjectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(&KeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE);
	HANDLE KeyHandle = nullptr;
	PKEY_VALUE_PARTIAL_INFORMATION KeyValuePartialInfo = nullptr;
	NTSTATUS Status = ZwOpenKey(&KeyHandle,
								KEY_ALL_ACCESS,
								&ObjectAttributes);
	if (!NT_SUCCESS(Status))
		return Status;

	ULONG Size;
	Status = ZwQueryValueKey(KeyHandle,
							&ValueName,
							KeyValuePartialInformation,
							nullptr,
							0,
							&Size);
	if (Status == STATUS_OBJECT_NAME_NOT_FOUND || Size == 0)
	{
		Status = STATUS_UNSUCCESSFUL;
		goto finished;
	}

	KeyValuePartialInfo = static_cast<PKEY_VALUE_PARTIAL_INFORMATION>(
		ExAllocatePoolWithTag(NonPagedPoolNx, Size, GetPoolTag()));
	Status = ZwQueryValueKey(KeyHandle,
							&ValueName,
							KeyValuePartialInformation,
							KeyValuePartialInfo,
							Size,
							&Size);
	if (!NT_SUCCESS(Status))
		goto finished;

	if (KeyValuePartialInfo == nullptr || KeyValuePartialInfo->Type != REG_SZ ||
		KeyValuePartialInfo->DataLength > ValueString->MaximumLength)
	{
		Status = STATUS_DATA_NOT_ACCEPTED;
		goto finished;
	}

	RtlZeroMemory(ValueString->Buffer, ValueString->MaximumLength);
	RtlCopyMemory(ValueString->Buffer, KeyValuePartialInfo->Data, KeyValuePartialInfo->DataLength);
	ValueString->Length = static_cast<USHORT>(KeyValuePartialInfo->DataLength) - sizeof(WCHAR);

finished:
	if (KeyHandle != nullptr)
		ObCloseHandle(KeyHandle, KernelMode);
	if (KeyValuePartialInfo != nullptr)
	{
		RtlSecureZeroMemory(KeyValuePartialInfo, KeyValuePartialInfo->DataLength);
		ExFreePool(KeyValuePartialInfo);
	}

	return Status;
}

NTSTATUS
RegQueryValueBoolean(
	_In_ PWSTR KeyNameBuffer,
	_In_ PWSTR ValueNameBuffer,
	_Out_ PBOOLEAN Value
	)
{
	PAGED_CODE();

	DECLARE_UNICODE_STRING_SIZE(ValueString, 2);
	DECLARE_UNICODE_STRING_SIZE(TrueString, 2);
	TrueString.Buffer[0] = L'1';
	TrueString.Buffer[1] = UNICODE_NULL;
	TrueString.Length = sizeof(L'1');

	const NTSTATUS Status = RegQueryValueString(KeyNameBuffer,
											ValueNameBuffer,
											&ValueString);
	*Value = RtlCompareUnicodeString(&ValueString,
									&TrueString,
									FALSE) == 0;
	return Status;
}

BOOLEAN
RtlUnicodeStringEndsIn(
	_In_ PCUNICODE_STRING String,
	_In_ PCUNICODE_STRING Substring
	)
{
	PAGED_CODE();

	if (Substring->Length > String->Length)
		return FALSE;

	const USHORT NumCharsDiff = (String->Length - Substring->Length) / sizeof(WCHAR);
	const PWCHAR EndOfString = String->Buffer + NumCharsDiff;
	return _wcsnicmp(EndOfString, Substring->Buffer, Substring->Length / sizeof(WCHAR)) == 0;
}

NTSTATUS
RtlStripPath(
	_In_ PUNICODE_STRING Path,
	_Out_ PUNICODE_STRING Name
	)
{
	PAGED_CODE();

	if (Path == nullptr || Name == nullptr)
		return STATUS_INVALID_PARAMETER;

	if (Path->Length < 2)
	{
		*Name = *Path;
		return STATUS_NOT_FOUND;
	}

	NTSTATUS Status = STATUS_NOT_FOUND;
	for (USHORT i = (Path->Length / sizeof(WCHAR)) - 1; i != 0; i--)
	{
		if (Path->Buffer[i] == L'\\' || Path->Buffer[i] == L'/')
		{
			Name->Buffer = &Path->Buffer[i + 1];
			Name->Length = Name->MaximumLength = Path->Length - (i + 1) * sizeof(WCHAR);
			Status = STATUS_SUCCESS;
			break;
		}
	}

	if (!NT_SUCCESS(Status))
		*Name = *Path;

	return Status;
}

NTSTATUS
RtlStripFilename(
	_In_ PUNICODE_STRING Path,
	_Out_ PUNICODE_STRING Directory
	)
{
	PAGED_CODE();

	if (Path == nullptr || Directory == nullptr)
		return STATUS_INVALID_PARAMETER;

	if (Path->Length < sizeof(WCHAR))
	{
		*Directory = *Path;
		return STATUS_NOT_FOUND;
	}

	for (USHORT i = (Path->Length / sizeof(WCHAR)) - 1; i != 0; i--)
	{
		if (Path->Buffer[i] == L'\\')
		{
			Directory->Length = Directory->MaximumLength = (i + 1) * sizeof(WCHAR);
			Directory->Buffer = Path->Buffer;
			return STATUS_SUCCESS;
		}
	}

	*Directory = *Path;
	return STATUS_NOT_FOUND;
}

NTSTATUS
RtlFileExists(
	_In_ PUNICODE_STRING NtPath
	)
{
	PAGED_CODE();

	OBJECT_ATTRIBUTES ObjectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(NtPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE);
	FILE_NETWORK_OPEN_INFORMATION FileInfo;
	const NTSTATUS Status = ZwQueryFullAttributesFile(&ObjectAttributes,
													&FileInfo);

	return ((FileInfo.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
		? STATUS_FILE_IS_A_DIRECTORY
		: Status;
}
