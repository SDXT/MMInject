#include "MMInject.h"
#include "vad.h"
#include "Utils.h"
#include "BlackBone/Loader.h"

#define IGNORE_IMPORT_HOOKS			0

#define LDR_IS_DATAFILE(x)			(((ULONG_PTR)(x)) & (ULONG_PTR)1)
#define LDR_DATAFILE_TO_VIEW(x)		((PVOID)(((ULONG_PTR)(x)) & ~(ULONG_PTR)1))

extern "C"
FORCEINLINE
PIMAGE_BASE_RELOCATION
LdrProcessRelocationBlock(
	_In_ ULONG_PTR VA,
	_In_ ULONG SizeOfBlock,
	_In_ PUSHORT NextOffset,
	_In_ LONGLONG Delta
	);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, LdrRelocateImageData)
#pragma alloc_text(PAGE, LdrProcessRelocationBlock)
#pragma alloc_text(PAGE, PatchGuardCFCheckFunctionPointers)
#pragma alloc_text(PAGE, InitializeStackCookie)
#pragma alloc_text(PAGE, ResolveImports)
#pragma alloc_text(PAGE, WipeImageSections)
#endif

extern DYNAMIC_DATA DynData;
extern t_NtProtectVirtualMemory NtProtectVirtualMemory;

PIMAGE_NT_HEADERS
NTAPI
RtlpImageNtHeaderEx(
	_In_ PVOID Base,
	_In_opt_ SIZE_T Size
	)
{
	const BOOLEAN RangeCheck = Size > 0;
	constexpr ULONG SizeOfPeSignature = 4;

	if (RangeCheck && Size < sizeof(IMAGE_DOS_HEADER))
		return nullptr;
	if (static_cast<PIMAGE_DOS_HEADER>(Base)->e_magic != IMAGE_DOS_SIGNATURE)
		return nullptr;

	const ULONG e_lfanew = static_cast<PIMAGE_DOS_HEADER>(Base)->e_lfanew;
	if (RangeCheck &&
		(e_lfanew >= Size ||
		e_lfanew >= (MAXULONG - SizeOfPeSignature - sizeof(IMAGE_FILE_HEADER)) ||
		e_lfanew + SizeOfPeSignature + sizeof(IMAGE_FILE_HEADER) >= Size))
	{
		return nullptr;
	}

	const PIMAGE_NT_HEADERS NtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<PCHAR>(Base) + e_lfanew);

	if (!RtlIsCanonicalAddress(reinterpret_cast<ULONG_PTR>(NtHeaders)))
		return nullptr;

#if (defined(_KERNEL_MODE) && (_KERNEL_MODE))
	if (reinterpret_cast<ULONG_PTR>(Base) < reinterpret_cast<ULONG_PTR>(MM_HIGHEST_USER_ADDRESS))
	{
		if (reinterpret_cast<ULONG_PTR>(NtHeaders) >= reinterpret_cast<ULONG_PTR>(MM_HIGHEST_USER_ADDRESS))
			return nullptr;

		if (reinterpret_cast<ULONG_PTR>(reinterpret_cast<PCHAR>(NtHeaders) + sizeof(IMAGE_NT_HEADERS)) >=
			reinterpret_cast<ULONG_PTR>(MM_HIGHEST_USER_ADDRESS))
			return nullptr;
	}
#endif

	if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return nullptr;

	return NtHeaders;
}

PVOID
GetProcedureAddress(
	_In_ ULONG_PTR DllBase,
	_In_ PCSTR RoutineName
	)
{
	const PIMAGE_DOS_HEADER DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(DllBase);
	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return nullptr;
	const PIMAGE_NT_HEADERS NtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(DllBase + DosHeader->e_lfanew);
	if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return nullptr;

	PIMAGE_DATA_DIRECTORY ImageDirectories;
	if (NtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		ImageDirectories = reinterpret_cast<PIMAGE_NT_HEADERS64>(NtHeaders)->OptionalHeader.DataDirectory;
	else
		ImageDirectories = reinterpret_cast<PIMAGE_NT_HEADERS32>(NtHeaders)->OptionalHeader.DataDirectory;

	const ULONG ExportDirRva = ImageDirectories[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	const ULONG ExportDirSize = ImageDirectories[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	const PIMAGE_EXPORT_DIRECTORY ExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(DllBase + ExportDirRva);
	const PULONG AddressOfFunctions = reinterpret_cast<PULONG>(DllBase + ExportDirectory->AddressOfFunctions);
	const PUSHORT AddressOfNameOrdinals = reinterpret_cast<PUSHORT>(DllBase + ExportDirectory->AddressOfNameOrdinals);
	const PULONG AddressOfNames = reinterpret_cast<PULONG>(DllBase + ExportDirectory->AddressOfNames);

	LONG Low = 0;
	LONG Middle = 0;
	LONG High = ExportDirectory->NumberOfNames - 1;

	while (High >= Low)
	{
		Middle = (Low + High) >> 1;
		const LONG Result = strcmp(RoutineName, reinterpret_cast<PCHAR>(DllBase + AddressOfNames[Middle]));
		if (Result < 0)
			High = Middle - 1;
		else if (Result > 0)
			Low = Middle + 1;
		else
			break;
	}

	if (High < Low || Middle >= static_cast<LONG>(ExportDirectory->NumberOfFunctions))
		return nullptr;
	const ULONG FunctionRva = AddressOfFunctions[AddressOfNameOrdinals[Middle]];
	if (FunctionRva >= ExportDirRva && FunctionRva < ExportDirRva + ExportDirSize)
		return nullptr;

	return reinterpret_cast<PVOID>(DllBase + FunctionRva);
}

PVOID
GetFileDataProcedureAddress(
	_In_ ULONG_PTR FileData,
	_In_ PCSTR RoutineName
	)
{
	const PIMAGE_DOS_HEADER DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(FileData);
	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return nullptr;
	const PIMAGE_NT_HEADERS NtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(FileData + DosHeader->e_lfanew);
	if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return nullptr;

	PIMAGE_DATA_DIRECTORY ImageDirectories;
	if (NtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		ImageDirectories = reinterpret_cast<PIMAGE_NT_HEADERS64>(NtHeaders)->OptionalHeader.DataDirectory;
	else
		ImageDirectories = reinterpret_cast<PIMAGE_NT_HEADERS32>(NtHeaders)->OptionalHeader.DataDirectory;

	const ULONG ExportDirRva = ImageDirectories[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	const ULONG ExportDirSize = ImageDirectories[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	const ULONG ExportDirOffset = RvaToOffset(NtHeaders, ExportDirRva);
	if (ExportDirOffset == 0)
		return nullptr;

	const PIMAGE_EXPORT_DIRECTORY ExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(FileData + ExportDirOffset);
	const ULONG AddressOfFunctionsOffset = RvaToOffset(NtHeaders, ExportDirectory->AddressOfFunctions);
	const ULONG AddressOfNameOrdinalsOffset = RvaToOffset(NtHeaders, ExportDirectory->AddressOfNameOrdinals);
	const ULONG AddressOfNamesOffset = RvaToOffset(NtHeaders, ExportDirectory->AddressOfNames);
	if (AddressOfFunctionsOffset == 0 || AddressOfNameOrdinalsOffset == 0 || AddressOfNamesOffset == 0)
		return nullptr;

	const PULONG AddressOfFunctions = reinterpret_cast<PULONG>(FileData + AddressOfFunctionsOffset);
	const PUSHORT AddressOfNameOrdinals = reinterpret_cast<PUSHORT>(FileData + AddressOfNameOrdinalsOffset);
	const PULONG AddressOfNames = reinterpret_cast<PULONG>(FileData + AddressOfNamesOffset);

	for (ULONG i = 0; i < ExportDirectory->NumberOfNames; ++i)
	{
		const ULONG NameOffset = RvaToOffset(NtHeaders, AddressOfNames[i]);
		if (NameOffset == 0)
			continue;

		const PCSTR FunctionName = reinterpret_cast<PSTR>(FileData + NameOffset);
		const ULONG FunctionRva = AddressOfFunctions[AddressOfNameOrdinals[i]];
		if (FunctionRva >= ExportDirRva && FunctionRva < ExportDirRva + ExportDirSize)
			continue;

		if (strcmp(FunctionName, RoutineName) == 0)
		{
			const ULONG ExportOffset = RvaToOffset(NtHeaders, FunctionRva);
			return ExportOffset != 0 ? reinterpret_cast<PVOID>(FileData + ExportOffset) : nullptr;
		}
	}

	return nullptr;
}

ULONG
RvaToOffset(
	_In_ PIMAGE_NT_HEADERS NtHeaders,
	_In_ ULONG Rva
	)
{
	PIMAGE_SECTION_HEADER SectionHeaders = IMAGE_FIRST_SECTION(NtHeaders);
	const USHORT NumberOfSections = NtHeaders->FileHeader.NumberOfSections;
	ULONG Result = 0;
	for (USHORT i = 0; i < NumberOfSections; ++i)
	{
		if (SectionHeaders->VirtualAddress <= Rva &&
			SectionHeaders->VirtualAddress + SectionHeaders->Misc.VirtualSize > Rva)
		{
			Result = Rva - SectionHeaders->VirtualAddress +
							SectionHeaders->PointerToRawData;
			break;
		}
		SectionHeaders++;
	}
	return Result;
}

PVOID
NTAPI
RtlpImageDirectoryEntryToDataEx(
	_In_ PVOID Base,
	_In_ BOOLEAN MappedAsImage,
	_In_ USHORT DirectoryEntry,
	_Out_ PULONG Size
	)
{
	if (LDR_IS_DATAFILE(Base))
	{
		Base = LDR_DATAFILE_TO_VIEW(Base);
		MappedAsImage = FALSE;
	}

	const PIMAGE_NT_HEADERS NtHeaders = RtlpImageNtHeaderEx(Base, 0);
	if (NtHeaders == nullptr)
		return nullptr;

	if (DirectoryEntry >= HEADER_FIELD(NtHeaders, NumberOfRvaAndSizes))
		return nullptr;

	const PIMAGE_DATA_DIRECTORY Directories = HEADER_FIELD(NtHeaders, DataDirectory);
	const ULONG Rva = Directories[DirectoryEntry].VirtualAddress;
	if (Rva == 0)
		return nullptr;

	if (reinterpret_cast<ULONG_PTR>(Base) < reinterpret_cast<ULONG_PTR>(MM_HIGHEST_USER_ADDRESS) &&
		reinterpret_cast<ULONG_PTR>(static_cast<PCHAR>(Base) + Rva) >= reinterpret_cast<ULONG_PTR>(MM_HIGHEST_USER_ADDRESS))
	{
		return nullptr;
	}

	*Size = Directories[DirectoryEntry].Size;
	if (MappedAsImage || Rva < HEADER_FIELD(NtHeaders, SizeOfHeaders))
	{
		return static_cast<PVOID>(static_cast<PCHAR>(Base) + Rva);
	}

	return static_cast<PVOID>(static_cast<PCHAR>(Base) + RvaToOffset(NtHeaders, Rva));
}

CONSTEXPR
ULONG
CharacteristicsToPageProtection(
	_In_ ULONG SectionCharacteristics
	)
{
	if ((SectionCharacteristics & IMAGE_SCN_MEM_WRITE) != 0)
	{
		return ((SectionCharacteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
			? PAGE_EXECUTE_READWRITE
			: PAGE_READWRITE;
	}
	if ((SectionCharacteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
	{
		return ((SectionCharacteristics & IMAGE_SCN_MEM_READ) != 0)
			? PAGE_EXECUTE_READ
			: PAGE_EXECUTE;
	}
	return ((SectionCharacteristics & IMAGE_SCN_MEM_READ) != 0)
			? PAGE_READONLY
			: PAGE_NOACCESS;
}

CONSTEXPR
BOOLEAN
IsVadProtectionChangeAllowed(
	_In_ PMMVAD_SHORT VadShort
	)
{
	if (VadShort->u.VadFlags.NoChange == 1UL)
		return FALSE;
	return VadShort->u.VadFlags.VadType == static_cast<ULONG>(VadNone) ||
		VadShort->u.VadFlags.VadType == static_cast<ULONG>(VadImageMap) ||
		VadShort->u.VadFlags.VadType == static_cast<ULONG>(VadAwe) ||
		VadShort->u.VadFlags.VadType == static_cast<ULONG>(VadRotatePhysical);
}

#if NTDDI_VERSION >= NTDDI_WIN10

CONSTEXPR
BOOLEAN
IsVadProtectionChangeAllowed19H1(
	_In_ PMMVAD_SHORT_19H1 VadShort
	)
{
	if (VadShort->u.VadFlags.NoChange == 1UL)
		return FALSE;
	return VadShort->u.VadFlags.VadType == static_cast<ULONG>(VadNone) ||
		VadShort->u.VadFlags.VadType == static_cast<ULONG>(VadImageMap) ||
		VadShort->u.VadFlags.VadType == static_cast<ULONG>(VadAwe) ||
		VadShort->u.VadFlags.VadType == static_cast<ULONG>(VadRotatePhysical);
}

#endif

FORCEINLINE
PIMAGE_BASE_RELOCATION
LdrProcessRelocationBlock(
	_In_ ULONG_PTR VA,
	_In_ ULONG SizeOfBlock,
	_In_ PUSHORT NextOffset,
	_In_ LONGLONG Delta
	)
{
	PAGED_CODE();

	LONG Temp;

	while (SizeOfBlock--)
	{
		const USHORT Offset = *NextOffset & static_cast<USHORT>(0xfff);
		const PUCHAR FixupVA = reinterpret_cast<PUCHAR>(VA + Offset);

		switch ((*NextOffset) >> 12)
		{
			case IMAGE_REL_BASED_HIGHLOW:

				*reinterpret_cast<LONG UNALIGNED *>(FixupVA) += static_cast<ULONG>(Delta);
				break;

			case IMAGE_REL_BASED_HIGH:
				Temp = *reinterpret_cast<PUSHORT>(FixupVA) << 16;
				Temp += static_cast<ULONG>(Delta);
				*reinterpret_cast<PUSHORT>(FixupVA) = static_cast<USHORT>(Temp >> 16);
				break;

			case IMAGE_REL_BASED_HIGHADJ:
				if (Offset & /*LDRP_RELOCATION_FINAL*/ 0x2)
				{
					++NextOffset;
					--SizeOfBlock;
					break;
				}

				Temp = *reinterpret_cast<PUSHORT>(FixupVA) << 16;
				++NextOffset;
				--SizeOfBlock;
				Temp += static_cast<LONG>(*reinterpret_cast<PSHORT>(NextOffset));
				Temp += static_cast<ULONG>(Delta);
				Temp += 0x8000;
				*reinterpret_cast<PUSHORT>(FixupVA) = static_cast<USHORT>(Temp >> 16);

				break;

			case IMAGE_REL_BASED_LOW:
				Temp = *reinterpret_cast<PSHORT>(FixupVA);
				Temp += static_cast<ULONG>(Delta);
				*reinterpret_cast<PUSHORT>(FixupVA) = static_cast<USHORT>(Temp);
				break;

			case IMAGE_REL_BASED_DIR64:
				*reinterpret_cast<ULONGLONG UNALIGNED*>(FixupVA) += Delta;
				break;

			case IMAGE_REL_BASED_ABSOLUTE:
				break;

			default:
				return nullptr;
		}
		++NextOffset;
	}

	return reinterpret_cast<PIMAGE_BASE_RELOCATION>(NextOffset);
}

NTSTATUS
LdrRelocateImageData(
	_In_ PVOID FileData,
	_In_ PVOID NewBase
	)
{
	PAGED_CODE();

	const PIMAGE_NT_HEADERS NtHeaders = RtlpImageNtHeaderEx(FileData, 0);
	const ULONG_PTR OldBase = static_cast<ULONG_PTR>(HEADER_FIELD(NtHeaders, ImageBase));

	ULONG NumBytes = 0;
	PIMAGE_BASE_RELOCATION NextBlock = static_cast<PIMAGE_BASE_RELOCATION>(
		RtlpImageDirectoryEntryToDataEx(FileData,
										FALSE,
										IMAGE_DIRECTORY_ENTRY_BASERELOC,
										&NumBytes));

	if (NextBlock == nullptr || NumBytes == 0)
	{
		return (NtHeaders->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
			? STATUS_CONFLICTING_ADDRESSES
			: STATUS_SUCCESS;
	}
	if (!(HEADER_FIELD(NtHeaders, DllCharacteristics) & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE))
	{
		Printf("Warning: force relocating an image without IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE but which does contain relocation data!\n");
		Printf("Either recompile with /DYNAMICBASE:YES, or (if this is intended) remove the relocation directory.\n");
	}

	const LONG_PTR Delta = reinterpret_cast<ULONG_PTR>(NewBase) - OldBase;

	while (NumBytes > 0)
	{
		ULONG SizeOfBlock = NextBlock->SizeOfBlock;
		if (SizeOfBlock == 0)
			return STATUS_INVALID_IMAGE_FORMAT;

		NumBytes -= SizeOfBlock;
		SizeOfBlock -= sizeof(IMAGE_BASE_RELOCATION);
		SizeOfBlock /= sizeof(USHORT);
		const PUSHORT NextOffset = reinterpret_cast<PUSHORT>(reinterpret_cast<PCHAR>(NextBlock) +
														sizeof(IMAGE_BASE_RELOCATION));

		const ULONG_PTR Offset = RvaToOffset(NtHeaders, NextBlock->VirtualAddress);
		const ULONG_PTR Address = reinterpret_cast<ULONG_PTR>(FileData) + Offset;

		NextBlock = LdrProcessRelocationBlock(Address,
											SizeOfBlock,
											NextOffset,
											Delta);
		if (NextBlock == nullptr)
			return STATUS_INVALID_IMAGE_FORMAT;
	}
	return STATUS_SUCCESS;
}

NTSTATUS
PatchGuardCFCheckFunctionPointers(
	_In_ PEPROCESS Process
	)
{
	PAGED_CODE();

	CONST PPEB Peb = PsGetProcessPeb(Process);
#ifdef _M_AMD64
	const PPEB32 Peb32 = static_cast<PPEB32>(PsGetProcessWow64Process(Process));
	const BOOLEAN IsWow64 = Peb32 != nullptr;
#else
	constexpr const PPEB32 Peb32 = nullptr;
	constexpr const BOOLEAN IsWow64 = FALSE;
#endif
	if (Peb == nullptr)
		return STATUS_NOT_FOUND;

	KAPC_STATE ApcState;
	KeStackAttachProcess(Process, &ApcState);

	CONST PIMAGE_NT_HEADERS NtHeaders = IsWow64
		? RtlpImageNtHeaderEx(reinterpret_cast<PVOID>(Peb32->ImageBaseAddress), 0)
		: RtlpImageNtHeaderEx(Peb->ImageBaseAddress, 0);
	NTSTATUS Status;
	if (NtHeaders == nullptr || HEADER_FIELD(NtHeaders, NumberOfRvaAndSizes) < IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
	{
		Status = STATUS_NOT_FOUND;
		goto finished;
	}

	ULONG Size = 0;
	CONST PIMAGE_LOAD_CONFIG_DIRECTORY32 LoadConfigDirectory32 = static_cast<PIMAGE_LOAD_CONFIG_DIRECTORY32>(
		RtlpImageDirectoryEntryToDataEx(Peb->ImageBaseAddress,
										TRUE,
										IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
										&Size));
	const PIMAGE_LOAD_CONFIG_DIRECTORY64 LoadConfigDirectory64 = reinterpret_cast<PIMAGE_LOAD_CONFIG_DIRECTORY64>(LoadConfigDirectory32);

	if (LoadConfigDirectory32 == nullptr ||
		(IMAGE32(NtHeaders) && (LoadConfigDirectory32->Size < FIELD_OFFSET(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardCFCheckFunctionPointer) ||
			LoadConfigDirectory32->GuardCFCheckFunctionPointer == 0)) ||
		(IMAGE64(NtHeaders) && (LoadConfigDirectory64->Size < FIELD_OFFSET(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardCFCheckFunctionPointer) ||
			LoadConfigDirectory64->GuardCFCheckFunctionPointer == 0))
		)
	{
		Status = STATUS_NOT_FOUND;
		goto finished;
	}

	PVOID LdrpValidateUserCallTarget, LdrpDispatchUserCallTarget = nullptr;
	__try
	{
		if (IsWow64)
		{
			const PULONG GuardCFCheckFunctionPointer = reinterpret_cast<PULONG>(LoadConfigDirectory32->GuardCFCheckFunctionPointer);
			LdrpValidateUserCallTarget = GuardCFCheckFunctionPointer != nullptr ? reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(*GuardCFCheckFunctionPointer)) : nullptr;
			Printf("\tGuardCFCheckFunctionPointer: 0x%04X -> 0x%04X\n",
				static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(GuardCFCheckFunctionPointer)), static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(LdrpValidateUserCallTarget)));
		}
		else
		{
			const PVOID* GuardCFCheckFunctionPointer = reinterpret_cast<PVOID*>(LoadConfigDirectory64->GuardCFCheckFunctionPointer);
			LdrpValidateUserCallTarget = GuardCFCheckFunctionPointer != nullptr ? *GuardCFCheckFunctionPointer : nullptr;
			Printf("\tGuardCFCheckFunctionPointer: 0x%p -> 0x%p\n",
				GuardCFCheckFunctionPointer, LdrpValidateUserCallTarget);
		}

#ifdef _M_AMD64
		if (!IsWow64)
		{
			PVOID* GuardCFDispatchFunctionPointer = reinterpret_cast<PVOID*>(LoadConfigDirectory64->GuardCFDispatchFunctionPointer);
			LdrpDispatchUserCallTarget = GuardCFDispatchFunctionPointer != nullptr ? *GuardCFDispatchFunctionPointer : nullptr;
			Printf("\tGuardCFDispatchFunctionPointer: 0x%p -> 0x%p\n",
				GuardCFDispatchFunctionPointer, LdrpDispatchUserCallTarget);
		}
#endif
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		Status = GetExceptionCode();
		goto finished;
	}

	if (LdrpValidateUserCallTarget == nullptr && LdrpDispatchUserCallTarget == nullptr)
	{
		Status = STATUS_SUCCESS;
		goto finished;
	}

	PVOID TargetPage = LdrpValidateUserCallTarget != nullptr ? LdrpValidateUserCallTarget : LdrpDispatchUserCallTarget;
	SIZE_T RegionSize = PAGE_SIZE;
	ULONG OldProtect;
	Status = NtProtectVirtualMemory(NtCurrentProcess(),
									&TargetPage,
									&RegionSize,
									PAGE_EXECUTE_READWRITE,
									&OldProtect);
	if (!NT_SUCCESS(Status))
		goto finished;

	UCHAR Validate64[] =
	{
		0x48, 0x8B, 0xC1,		// mov rax, rcx
		0x48, 0xC1, 0xE8, 0x03,	// shr rax, 3
		0xC3					// ret
	};

	UCHAR Validate32[] =
	{
		0xC2, 0x00, 0x00		// ret 0
	};

	if (LdrpValidateUserCallTarget != nullptr)
		RtlCopyMemory(LdrpValidateUserCallTarget, IsWow64 ? Validate32 : Validate64, IsWow64 ? sizeof(Validate32) : sizeof(Validate64));

#ifdef _WIN64
	UCHAR Dispatch[] = { 0x48, 0xFF, 0xE0 }; // jmp rax
	if (LdrpDispatchUserCallTarget != nullptr)
		RtlCopyMemory(LdrpDispatchUserCallTarget, Dispatch, sizeof(Dispatch));
#endif

	Status = NtProtectVirtualMemory(NtCurrentProcess(),
									&TargetPage,
									&RegionSize,
									OldProtect,
									&OldProtect);

finished:
	KeUnstackDetachProcess(&ApcState);

	return Status;
}

FORCEINLINE
LARGE_INTEGER
RtlQueryPerformanceCounter(
	_Out_opt_ PLARGE_INTEGER PerformanceFrequency
	)
{
	const UCHAR QpcShift = SharedUserData->QpcShift != 0 ? SharedUserData->QpcShift : 0xA;
	const ULONG64 Tsc = __rdtsc();
	LARGE_INTEGER Result;
	Result.QuadPart = (SharedUserData->QpcBias +
		((static_cast<ULONG64>(static_cast<ULONG>((Tsc >> 32) & 0xFFFFFFFF)) << 32) |
			static_cast<ULONG>(Tsc))) >> QpcShift;
	if (PerformanceFrequency != nullptr)
#ifdef _WIN64
		PerformanceFrequency->QuadPart = static_cast<ULONG_PTR>(__readgsqword(0x0C0)) >> QpcShift;
#else
		PerformanceFrequency->QuadPart = SharedUserData->QpcFrequency;
#endif
	return Result;
}

VOID
InitializeStackCookie(
	_In_ PVOID ImageBase,
	_In_ PCLIENT_ID ClientId
	)
{
	PAGED_CODE();
	
	const PIMAGE_NT_HEADERS NtHeaders = RtlpImageNtHeaderEx(ImageBase, 0);
	if (HEADER_FIELD(NtHeaders, MajorSubsystemVersion) < 6 || (HEADER_FIELD(NtHeaders, MajorSubsystemVersion) == 6 && HEADER_FIELD(NtHeaders, MinorSubsystemVersion < 3)))
		return; 

	ULONG ConfigDirSize = 0;
	const PIMAGE_LOAD_CONFIG_DIRECTORY32 LoadConfigDirectory32 = static_cast<PIMAGE_LOAD_CONFIG_DIRECTORY32>(
		RtlpImageDirectoryEntryToDataEx(ImageBase,
										TRUE,
										IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
										&ConfigDirSize));
	const PIMAGE_LOAD_CONFIG_DIRECTORY64 LoadConfigDirectory64 = reinterpret_cast<PIMAGE_LOAD_CONFIG_DIRECTORY64>(LoadConfigDirectory32);

	if (LoadConfigDirectory32 == nullptr || ConfigDirSize == 0)
		return;

	const ULONG SizeOfCookie = IMAGE64(NtHeaders) ? sizeof(ULONG64) : sizeof(ULONG);
	ULONG_PTR CookieVA, DefaultSecurityCookie;
	UINT_PTR Cookie;

	if (IMAGE64(NtHeaders))
	{
		if ((CookieVA = LoadConfigDirectory64->SecurityCookie) == 0)
			return;

		Cookie = static_cast<ULONG64>(SharedUserData->SystemTime.High1Time) << 32 |
				static_cast<ULONG64>(SharedUserData->SystemTime.LowPart);
	}
	else
	{
		if ((CookieVA = LoadConfigDirectory32->SecurityCookie) == 0)
			return;
		
		Cookie = SharedUserData->SystemTime.LowPart;
		Cookie ^= SharedUserData->SystemTime.High1Time;
	}

	Cookie ^= HandleToULong(ClientId->UniqueThread);
	Cookie ^= HandleToULong(ClientId->UniqueProcess);

	const ULONG64 TickCount64 = (SharedUserData->TickCountMultiplier * SharedUserData->TickCountQuad >> 24) +
						(SharedUserData->TickCountMultiplier * (SharedUserData->TickCountQuad >> 32) << 8);
	Cookie ^= (IMAGE64(NtHeaders) ? (TickCount64 << 56) : TickCount64);

	const LARGE_INTEGER PerfCounter = RtlQueryPerformanceCounter(nullptr);

	if (IMAGE64(NtHeaders))
	{
		Cookie ^= (static_cast<ULONG64>(PerfCounter.LowPart) << 32) ^ PerfCounter.QuadPart;

		Cookie ^= CookieVA;

		Cookie &= 0x0000FFFFFFFFFFFFi64;

		DefaultSecurityCookie = static_cast<ULONG_PTR>(0x00002B992DDFA232ULL);
		if (Cookie == DefaultSecurityCookie)
			Cookie++;
	}
	else
	{
		Cookie ^= PerfCounter.LowPart;
		Cookie ^= PerfCounter.HighPart;

		Cookie ^= CookieVA;

		DefaultSecurityCookie = 0xBB40E64E;
		if (Cookie == DefaultSecurityCookie)
			Cookie++;
		else if ((Cookie & 0xFFFF0000) == 0)
			Cookie |= ((Cookie | 0x4711) << 16);
	}

	ULONG_PTR CookieComplementVA = CookieVA + SizeOfCookie;
	if ((IMAGE64(NtHeaders) && *reinterpret_cast<PULONG_PTR>(CookieComplementVA) != ~DefaultSecurityCookie) ||
		(IMAGE32(NtHeaders) && *reinterpret_cast<PULONG>(CookieComplementVA) != ~DefaultSecurityCookie))
	{
		CookieComplementVA = CookieVA - SizeOfCookie;
		if ((IMAGE64(NtHeaders) && *reinterpret_cast<PULONG_PTR>(CookieComplementVA) != ~DefaultSecurityCookie) ||
			(IMAGE32(NtHeaders) && *reinterpret_cast<PULONG>(CookieComplementVA) != ~DefaultSecurityCookie))
			CookieComplementVA = 0; 
	}

	if (IMAGE64(NtHeaders))
	{
		*reinterpret_cast<PULONG_PTR>(CookieVA) = Cookie;
		if (CookieComplementVA != 0)
			*reinterpret_cast<PULONG_PTR>(CookieComplementVA) = ~Cookie;
	}
	else
	{
		*reinterpret_cast<PULONG>(CookieVA) = static_cast<ULONG>(Cookie);
		if (CookieComplementVA != 0)
			*reinterpret_cast<PULONG>(CookieComplementVA) = ~static_cast<ULONG>(Cookie);
	}
}

PVOID
RandomiseImageBase(
	_In_ PIMAGE_NT_HEADERS NtHeaders,
	_In_opt_ PVOID PreferredBase
	)
{
	PreferredBase = PreferredBase != nullptr ? PreferredBase : reinterpret_cast<PVOID>(HEADER_FIELD(NtHeaders, ImageBase));

	
	const ULONG MaxBias = IMAGE64(NtHeaders) ? 0x20000000UL : 0x20000UL;
	const ULONG Bias = RtlNextRandom(0, MaxBias);

	
	const ULONG_PTR Multiplier = IMAGE64(NtHeaders) ? 0x10 : 0x1;
	const ULONG_PTR ShiftedImageBase = reinterpret_cast<ULONG_PTR>(PreferredBase) + (Bias << 1);
	return reinterpret_cast<PVOID>((ShiftedImageBase + (Multiplier * PAGE_SIZE) - 1) & ~((Multiplier * PAGE_SIZE) - 1));
}

PVOID
RandomiseSystemImageBase(
	_In_ PEPROCESS Process,
	_In_ PIMAGE_NT_HEADERS NtHeaders
	)
{
	ULONG_PTR Start = static_cast<ULONG_PTR>(IMAGE64(NtHeaders) ?
		(DynData.Version >= WINVER_81 ? 0x7f0000000000 : 0x7f000000000) :
		0x70000000);

	const ULONG_PTR MmHighestVadAddress = reinterpret_cast<ULONG_PTR>(MM_HIGHEST_USER_ADDRESS) - (64 * 1024);
	while (true)
	{
		const ULONG_PTR End = Start + ROUND_TO_PAGES(HEADER_FIELD(NtHeaders, SizeOfImage));
		if (End > MmHighestVadAddress)
		{
			Printf("Failed to find available system DLL range for image! Falling back to default image base\n");
			return RandomiseImageBase(NtHeaders, nullptr);
		}

		if (!DoesVADConflict(Process, Start, End))
		{
			const ULONG_PTR ShiftedStart = reinterpret_cast<ULONG_PTR>(RandomiseImageBase(NtHeaders, reinterpret_cast<PVOID>(Start)));
			const ULONG_PTR ShiftedEnd = ShiftedStart + ROUND_TO_PAGES(HEADER_FIELD(NtHeaders, SizeOfImage));

			if (!DoesVADConflict(Process, ShiftedStart, ShiftedEnd))
			{
				return reinterpret_cast<PVOID>(ShiftedStart);
			}

			
			Printf("Could not apply ASLR (0x%p -> 0x%p): virtual address range conflicts with an existing VAD\n",
				reinterpret_cast<PVOID>(Start), reinterpret_cast<PVOID>(ShiftedStart));
			return reinterpret_cast<PVOID>(Start);
		}

		Start += ((IMAGE64(NtHeaders) ? 128 : 16) * 1024 * 1024);
	}
}

NTSTATUS
ResolveImports(
	_In_ PEPROCESS Process,
	_In_ PVOID ImageBase,
	_In_ BOOLEAN WipeNames
	)
{
	PAGED_CODE();

	NTSTATUS Status = STATUS_SUCCESS;
	ULONG ImportsSize = 0;
	const PIMAGE_NT_HEADERS NtHeaders = RtlpImageNtHeaderEx(ImageBase, 0);
	PIMAGE_IMPORT_DESCRIPTOR ImportTable = static_cast<PIMAGE_IMPORT_DESCRIPTOR>(
		RtlpImageDirectoryEntryToDataEx(ImageBase,
										TRUE,
										IMAGE_DIRECTORY_ENTRY_IMPORT,
										&ImportsSize));

	if (ImportTable == nullptr)
		return STATUS_SUCCESS;

	BOOLEAN Hooked = FALSE;

	for ( ; ImportTable->Name && NT_SUCCESS(Status); ++ImportTable)
	{
		PVOID Thunk = static_cast<PUCHAR>(ImageBase) + (ImportTable->OriginalFirstThunk
			? ImportTable->OriginalFirstThunk
			: ImportTable->FirstThunk);

		DECLARE_UNICODE_STRING_SIZE(UnicodeDllName, 1024);
		UNICODE_STRING ResolvedDllPath = { 0 }, ResolvedDllName = { 0 };
		ANSI_STRING AnsiDllName;
		PUCHAR VerificationDllBuffer = nullptr;
		ULONG IatIndex = 0;

		RtlxInitAnsiString(&AnsiDllName, static_cast<PCHAR>(ImageBase) + ImportTable->Name);
		RtlAnsiStringToUnicodeString(&UnicodeDllName, &AnsiDllName, FALSE);

		if (WipeNames)
		{
			RtlFillGarbageMemory(static_cast<PCHAR>(ImageBase) + ImportTable->Name, AnsiDllName.MaximumLength);
		}

		Status = ResolveImagePath(Process, &UnicodeDllName, &ResolvedDllPath);
		if (!NT_SUCCESS(Status))
		{
			Printf("Failed to resolve full path for DLL %wZ: %08X\n", &UnicodeDllName, Status);
			return Status;
		}

		RtlStripPath(&ResolvedDllPath, &ResolvedDllName);
		Printf("Processing imports for %wZ...\n", &ResolvedDllName);

		const PVOID ModuleAddress = FindModule(Process, &ResolvedDllName);
		if (ModuleAddress == nullptr)
		{
			NT_ASSERT(FALSE);
		}

		if (ModuleAddress == nullptr)
		{
			Printf("Failed to find loaded DLL '%wZ': status 0x%08X\n", &UnicodeDllName, Status);
			RtlxFreeUnicodeString(&ResolvedDllPath);
			return STATUS_NOT_FOUND;
		}

		Status = RtlReadFileToBytes(&ResolvedDllPath, &VerificationDllBuffer, nullptr);
		if (!NT_SUCCESS(Status))
		{
			Printf("Failed to read DLL '%wZ' from disk for hook checking: status 0x%08X\n", &UnicodeDllName, Status);
			RtlxFreeUnicodeString(&ResolvedDllPath);
			return Status;
		}

		while (THUNK_VAL(NtHeaders, Thunk, u1.AddressOfData) != 0)
		{
			ANSI_STRING AnsiFunctionName;
			CHAR ImportFunctionNameBuffer[1024] = { '\0' }, *ImportFunctionName;
			BOOLEAN ImportByOrdinal = FALSE;

			const PIMAGE_IMPORT_BY_NAME AddressTable = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
				static_cast<PUCHAR>(ImageBase) + THUNK_VAL(NtHeaders, Thunk, u1.AddressOfData));
			
			if (THUNK_VAL(NtHeaders, Thunk, u1.AddressOfData) < (IMAGE64(NtHeaders) ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32) &&
				 AddressTable->Name[0] != '\0')
			{
				RtlxInitAnsiString(&AnsiFunctionName, AddressTable->Name);
				strncpy_s(ImportFunctionNameBuffer, sizeof(ImportFunctionNameBuffer), AddressTable->Name, AnsiFunctionName.Length);
				ImportFunctionName = ImportFunctionNameBuffer;

				if (WipeNames)
				{
					RtlFillGarbageMemory(AddressTable->Name - FIELD_OFFSET(IMAGE_IMPORT_BY_NAME, Name),
						AnsiFunctionName.MaximumLength + FIELD_OFFSET(IMAGE_IMPORT_BY_NAME, Name));
				}
			}
			else
			{
				ImportByOrdinal = TRUE;
				ImportFunctionName = reinterpret_cast<PCCHAR>(THUNK_VAL(NtHeaders, Thunk, u1.AddressOfData) & 0xFFFF);
			}

			PVOID Function = GetModuleExport(ModuleAddress,
											ImportFunctionName,
											Process);
			
			if (Function == nullptr)
			{
				if (THUNK_VAL(NtHeaders, Thunk, u1.AddressOfData) <
					(IMAGE64(NtHeaders) ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32) && ImportFunctionNameBuffer[0] != '\0')
					Printf(" Failed to resolve import '%wZ!%hs'\n",
						&UnicodeDllName, ImportFunctionNameBuffer);
				else
					Printf("Failed to resolve import '%wZ!#%zu'\n",
						&UnicodeDllName, THUNK_VAL(NtHeaders, Thunk, u1.AddressOfData) & 0xFFFF);

				Status = STATUS_NOT_FOUND;
				break;
			}

			const PVOID FunctionOnDisk = ImportByOrdinal
				? nullptr
				: GetFileDataProcedureAddress(reinterpret_cast<ULONG_PTR>(VerificationDllBuffer), ImportFunctionNameBuffer);

			if (FunctionOnDisk != nullptr)
			{
				for (ULONG i = 0; i < 3; ++i)
				{
					const UCHAR ByteOnDisk = static_cast<PUCHAR>(FunctionOnDisk)[i];
					const UCHAR ByteInProcess = static_cast<PUCHAR>(Function)[i];

					if (ByteOnDisk != ByteInProcess)
					{
						Printf("%wZ!%hs[%lu]: expected 0x%02X, found 0x%02X. Imported function is HOOKED!\n",
							&UnicodeDllName, ImportFunctionNameBuffer, i, ByteOnDisk, ByteInProcess);
						Hooked = TRUE;
					}
				}
			}

			if (IMAGE64(NtHeaders))
			{
				if (ImportTable->FirstThunk != 0)
					*reinterpret_cast<PULONG_PTR>(static_cast<PUCHAR>(ImageBase) + ImportTable->FirstThunk + IatIndex) =
					reinterpret_cast<ULONG_PTR>(Function);
				else
					*reinterpret_cast<PULONG_PTR>(static_cast<PUCHAR>(ImageBase) + THUNK_VAL(NtHeaders, Thunk, u1.AddressOfData)) =
					reinterpret_cast<ULONG_PTR>(Function);
			}
			else
			{
				if (ImportTable->FirstThunk != 0)
					*reinterpret_cast<PULONG>(static_cast<PUCHAR>(ImageBase) + ImportTable->FirstThunk + IatIndex) =
					static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(Function));
				else
					*reinterpret_cast<PULONG>(static_cast<PUCHAR>(ImageBase) + THUNK_VAL(NtHeaders, Thunk, u1.AddressOfData)) =
					static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(Function));
			}

			Thunk = static_cast<PUCHAR>(Thunk) + (IMAGE64(NtHeaders) ? sizeof(IMAGE_THUNK_DATA64) : sizeof(IMAGE_THUNK_DATA32));
			IatIndex += (IMAGE64(NtHeaders) ? sizeof(ULONGLONG) : sizeof(ULONG));
		}

		RtlxFreeUnicodeString(&ResolvedDllPath);

		if (VerificationDllBuffer != nullptr)
			ExFreePool(VerificationDllBuffer);
	}

#if !IGNORE_IMPORT_HOOKS
	if (NT_SUCCESS(Status) && Hooked)
	{
		Printf("Aborting import resolution; DLL imports one or more hooked function(s)\n");
		Status = STATUS_DATA_NOT_ACCEPTED;
	}
#endif

	return Status;
}

VOID
WipeImageSections(
	_In_ PVOID ImageBase,
	_In_ BOOLEAN PhysicalAllocation,
	_In_ PIMAGE_SECTION_HEADER SectionHeaders,
	_In_ BOOLEAN WipeHeaders
	)
{
	PAGED_CODE();

	const PIMAGE_NT_HEADERS NtHeaders = RtlpImageNtHeaderEx(ImageBase, 0);
	const int NumberOfSections = static_cast<int>(NtHeaders->FileHeader.NumberOfSections);

	for (LONG i = NumberOfSections - 1; i >= -1; --i)
	{
		if ((i == -1 && !WipeHeaders) ||
			(i >= 0 && (SectionHeaders[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0))
			continue;

		PVOID SectionVa;
		SIZE_T SectionVirtualSize;
		if (i == -1)
		{
			SectionVa = ImageBase;
			SectionVirtualSize = ALIGN_TO_SECTIONS(HEADER_FIELD(NtHeaders, SizeOfHeaders), HEADER_FIELD(NtHeaders, SectionAlignment));
			Printf("Wiping PE headers at 0x%p (size 0x%X)...\n", SectionVa, static_cast<ULONG>(SectionVirtualSize));
		}
		else
		{
			SectionVa = static_cast<PVOID>(static_cast<PUCHAR>(ImageBase) + SectionHeaders[i].VirtualAddress);
			SectionVirtualSize = SectionHeaders[i].Misc.VirtualSize > 0
				? SectionHeaders[i].Misc.VirtualSize
				: SectionHeaders[i].SizeOfRawData;
			SectionVirtualSize = ALIGN_TO_SECTIONS(SectionVirtualSize, HEADER_FIELD(NtHeaders, SectionAlignment));
			SectionHeaders[i].Name[IMAGE_SIZEOF_SHORT_NAME - 1] = '\0';
			Printf("Wiping section \"%hs\" at 0x%p (size 0x%X)...\n",
				reinterpret_cast<PCCH>(SectionHeaders[i].Name), SectionVa, static_cast<ULONG>(SectionVirtualSize));
		}

		RtlFillGarbageMemory(SectionVa, SectionVirtualSize);

		if (PhysicalAllocation)
		{
			PMMVAD_SHORT VadShort;
			if (!NT_SUCCESS(FindVAD(PsGetCurrentProcess(), reinterpret_cast<ULONG_PTR>(SectionVa), &VadShort)))
				continue;

#if NTDDI_VERSION >= NTDDI_WIN10
			if ((DynData.Version >= WINVER_10_19H1 && !IsVadProtectionChangeAllowed19H1(reinterpret_cast<PMMVAD_SHORT_19H1>(VadShort))) ||
				(DynData.Version < WINVER_10_19H1 && !IsVadProtectionChangeAllowed(VadShort)))
#else
			if (!IsVadProtectionChangeAllowed(VadShort))
#endif
			{
				if (i == -1)
				{
					const PMMPTE PTE = GetPTEForVA(reinterpret_cast<PVOID>(SectionVa));
					PTE->u.Hard.Dirty1 = PTE->u.Hard.Write = 0;
					PTE->u.Hard.NoExecute = 1;
				}
				continue;
			}
		}

		ULONG OldProtect;
		if (NT_SUCCESS(NtProtectVirtualMemory(NtCurrentProcess(),
											&SectionVa,
											&SectionVirtualSize,
											PAGE_NOACCESS,
											&OldProtect)))
		{
			NtFreeVirtualMemory(NtCurrentProcess(),
								&SectionVa,
								&SectionVirtualSize,
								MEM_DECOMMIT);
		}
	}
}
