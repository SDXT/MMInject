#include "MMInject.h"
#include "StringEncryptor.h"
#include "Loader.h"
#include "Utils.h"
#include <ntstrsafe.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, FindModule)
#pragma alloc_text(PAGE, GetModuleExport)
#pragma alloc_text(PAGE, ResolveImagePath)
#endif

PVOID
FindModule(
	_In_ PEPROCESS Process,
	_In_ PUNICODE_STRING ModuleName
	)
{
	PAGED_CODE();

#ifdef _M_AMD64
	const PPEB32 Peb32 = static_cast<PPEB32>(PsGetProcessWow64Process(Process));
	const BOOLEAN IsWow64 = Peb32 != nullptr;
#else
	constexpr PPEB32 Peb32 = nullptr;
	constexpr BOOLEAN IsWow64 = FALSE;
#endif

	CONSTEXPR LONGLONG LoaderTimeoutMs = 300LL;
	CONSTEXPR ULONG LoaderRetries = 15;

	__try
	{
		if (IsWow64)
		{
			for (ULONG i = 0; !Peb32->Ldr && i < LoaderRetries; ++i)
			{
				Printf("FindModule: Loader not initialized, waiting...\n");
				LARGE_INTEGER Timeout;
				Timeout.QuadPart = -10LL * 1000LL * LoaderTimeoutMs;
				KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
			}
			
			if (Peb32->Ldr == 0)
			{
				Printf("FindModule: Loader was not initialized in time. Aborting\n");
				return nullptr;
			}

			for (PLIST_ENTRY32 ListEntry = reinterpret_cast<PLIST_ENTRY32>(reinterpret_cast<PPEB_LDR_DATA32>(Peb32->Ldr)->InLoadOrderModuleList.Flink);
				ListEntry != &reinterpret_cast<PPEB_LDR_DATA32>(Peb32->Ldr)->InLoadOrderModuleList;
				ListEntry = reinterpret_cast<PLIST_ENTRY32>(ListEntry->Flink))
			{
				const PLDR_DATA_TABLE_ENTRY32 Entry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
				DECLARE_UNICODE_STRING_SIZE(BaseDllName, MAX_PATH);

				RtlxInitUnicodeString(&BaseDllName, reinterpret_cast<PWCHAR>(Entry->BaseDllName.Buffer));
				if (RtlCompareUnicodeString(&BaseDllName, ModuleName, TRUE) == 0)
					return reinterpret_cast<PVOID>(Entry->DllBase);
			}
		}
		else
		{
			PPEB Peb = PsGetProcessPeb(Process);
			if (Peb == nullptr)
			{
				Printf("FindModule: No PEB present. Aborting\n");
				return nullptr;
			}

			for (ULONG i = 0; !Peb->Ldr && i < LoaderRetries; ++i)
			{
				Printf("FindModule: Loader not initialized, waiting...\n");
				LARGE_INTEGER Timeout;
				Timeout.QuadPart = -10LL * 1000LL * LoaderTimeoutMs;
				KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
			}
		
			if (Peb->Ldr == nullptr)
			{
				Printf("FindModule: Loader was not initialized in time. Aborting\n");
				return nullptr;
			}

			for (PLIST_ENTRY ListEntry = Peb->Ldr->InLoadOrderModuleList.Flink;
				 ListEntry != &Peb->Ldr->InLoadOrderModuleList;
				 ListEntry = ListEntry->Flink)
			{
				PLDR_DATA_TABLE_ENTRY Entry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
				if (RtlCompareUnicodeString(&Entry->BaseDllName, ModuleName, TRUE) == 0)
					return Entry->DllBase;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		Printf("FindModule: exception %08X\n", GetExceptionCode());
	}
	return nullptr;
}

PVOID
GetModuleExport(
	_In_ PVOID Base,
	_In_ PCCHAR NameOrOrdinal,
	_In_ PEPROCESS Process
	)
{
	PAGED_CODE();
	
	PIMAGE_EXPORT_DIRECTORY ExportDir;
	ULONG ExportDirSize;
	ULONG_PTR FunctionAddress = 0;
	
	const PIMAGE_DOS_HEADER DosHeaders = static_cast<PIMAGE_DOS_HEADER>(Base);
	if (DosHeaders->e_magic != IMAGE_DOS_SIGNATURE)
		return nullptr;

	const PIMAGE_NT_HEADERS32 NtHeaders32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(static_cast<PUCHAR>(Base) + DosHeaders->e_lfanew);
	const PIMAGE_NT_HEADERS64 NtHeaders64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(static_cast<PUCHAR>(Base) + DosHeaders->e_lfanew);
	
	if (NtHeaders32->Signature != IMAGE_NT_SIGNATURE)
		return nullptr;

	if (NtHeaders32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		// x64 image
		ExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(NtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress +
			reinterpret_cast<ULONG_PTR>(Base));
		ExportDirSize = NtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	}
	else
	{
		// x86 image
		ExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(NtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress +
			reinterpret_cast<ULONG_PTR>(Base));
		ExportDirSize = NtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	}

	const PUSHORT AddressOfOrdinals = reinterpret_cast<PUSHORT>(ExportDir->AddressOfNameOrdinals + reinterpret_cast<ULONG_PTR>(Base));
	const PULONG AddressOfNames = reinterpret_cast<PULONG>(ExportDir->AddressOfNames + reinterpret_cast<ULONG_PTR>(Base));
	const PULONG AddressOfFunctions = reinterpret_cast<PULONG>(ExportDir->AddressOfFunctions + reinterpret_cast<ULONG_PTR>(Base));

	for (ULONG i = 0; i < ExportDir->NumberOfFunctions; ++i)
	{
		USHORT OrdinalIndex;
		PCHAR Name = nullptr;
		
		if (reinterpret_cast<ULONG_PTR>(NameOrOrdinal) <= 0xFFFF)
		{
			OrdinalIndex = static_cast<USHORT>(i);
		}
		else if (reinterpret_cast<ULONG_PTR>(NameOrOrdinal) > 0xFFFF && i < ExportDir->NumberOfNames)
		{
			Name = reinterpret_cast<PCHAR>(AddressOfNames[i] + reinterpret_cast<ULONG_PTR>(Base));
			OrdinalIndex = AddressOfOrdinals[i];
		}
		else
			return nullptr;

		if ((reinterpret_cast<ULONG_PTR>(NameOrOrdinal) <= 0xFFFF &&
			static_cast<USHORT>(reinterpret_cast<ULONG_PTR>(NameOrOrdinal)) == OrdinalIndex + ExportDir->Base) ||
			(reinterpret_cast<ULONG_PTR>(NameOrOrdinal) > 0xFFFF && strcmp(Name, NameOrOrdinal) == 0))
		{
			FunctionAddress = AddressOfFunctions[OrdinalIndex] + reinterpret_cast<ULONG_PTR>(Base);

			if (FunctionAddress >= reinterpret_cast<ULONG_PTR>(ExportDir) &&
				FunctionAddress <= reinterpret_cast<ULONG_PTR>(ExportDir) + ExportDirSize)
			{
				ANSI_STRING AnsiForwarderDll = { 0 };
				DECLARE_UNICODE_STRING_SIZE(ForwarderDll, 256);

				RtlxInitAnsiString(&AnsiForwarderDll, reinterpret_cast<PCSZ>(FunctionAddress));
				RtlAnsiStringToUnicodeString(&ForwarderDll, &AnsiForwarderDll, FALSE);

				ULONG DelimPos = 0;
				for (ULONG j = 0; j < ForwarderDll.Length / sizeof(WCHAR); j++)
				{
					if (ForwarderDll.Buffer[j] == L'.')
					{
						ForwarderDll.Length = static_cast<USHORT>(j * sizeof(WCHAR));
						ForwarderDll.Buffer[j] = UNICODE_NULL;
						DelimPos = j;
						break;
					}
				}

				ANSI_STRING ImportName = { 0 };
				RtlxInitAnsiString(&ImportName, AnsiForwarderDll.Buffer + DelimPos + 1);

				PWCHAR ForwarderBuffer = &ForwarderDll.Buffer[ForwarderDll.Length / sizeof(WCHAR)];
				*ForwarderBuffer++ = L'.';
				*ForwarderBuffer++ = L'd';
				*ForwarderBuffer++ = L'l';
				*ForwarderBuffer++ = L'l';
				*ForwarderBuffer = UNICODE_NULL;
				ForwarderDll.Length += sizeof(L".dll") - sizeof(WCHAR);

				UNICODE_STRING ResolvedForwarderDllPath = { 0 }, ResolvedName = { 0 };
				ResolveImagePath(Process, &ForwarderDll, &ResolvedForwarderDllPath);
				if (ResolvedForwarderDllPath.Length == 0)
					return nullptr;

				RtlStripPath(&ResolvedForwarderDllPath, &ResolvedName);

				const PVOID ForwardBase = FindModule(Process, &ResolvedName);
				const PVOID Result = ForwardBase != nullptr
					? GetModuleExport(ForwardBase, ImportName.Buffer, Process)
					: nullptr;

				RtlxFreeUnicodeString(&ResolvedForwarderDllPath);

				return Result;
			}

			break;
		}
	}
	return reinterpret_cast<PVOID>(FunctionAddress);
}

NTSTATUS
ResolveImagePath(
	_In_ PEPROCESS Process,
	_In_ PUNICODE_STRING Path,
	_Inout_ PUNICODE_STRING Resolved
	)
{
	PAGED_CODE();

#ifndef _WIN64
	UNREFERENCED_PARAMETER(Process);
#endif

	UNICODE_STRING FileName = { 0 };
	RtlStripPath(Path, &FileName);

	UNICODE_STRING FullResolved =
	{
		0,
		512 * sizeof(WCHAR),
		static_cast<PWCH>(ExAllocatePoolWithTag(NonPagedPoolNx, 512 * sizeof(WCHAR), GetPoolTag()))
	};
	RtlZeroMemory(FullResolved.Buffer, FullResolved.MaximumLength);

	if (NT_SUCCESS(NtQueryInformationProcess(NtCurrentProcess(),
											ProcessImageFileName,
											FullResolved.Buffer + 256,
											FullResolved.MaximumLength / sizeof(WCHAR),
											nullptr)))
	{
		const PUNICODE_STRING PathString = reinterpret_cast<PUNICODE_STRING>(FullResolved.Buffer + 256);
		UNICODE_STRING ParentDir;
		RtlStripFilename(PathString, &ParentDir);

		RtlxCopyUnicodeString(&FullResolved, &ParentDir);
		RtlUnicodeStringCat(&FullResolved, &FileName);
		BOOLEAN FileExists = FALSE;

		if (NT_SUCCESS(RtlFileExists(&FullResolved)))
		{
			RtlxFreeUnicodeString(Resolved);

			*Resolved = FullResolved;
			FileExists = TRUE;
		}

		if (FileExists)
			return STATUS_SUCCESS;
	}

	FullResolved.Length = 0;
	RtlSecureZeroMemory(FullResolved.Buffer, FullResolved.MaximumLength);

#ifdef _WIN64
	if (PsGetProcessWow64Process(Process) != nullptr)
	{
#endif
		WCHAR SysWOW64Path[decltype(EncryptedSysWOW64PathString)::Length];
		DecryptString(EncryptedSysWOW64PathString, SysWOW64Path);
		RtlUnicodeStringCatString(&FullResolved, SysWOW64Path);
		RtlSecureZeroMemory(SysWOW64Path, decltype(EncryptedSysWOW64PathString)::Length);
#ifdef _WIN64
	}
	else
	{
#endif
		WCHAR System32Path[decltype(EncryptedSystem32PathString)::Length];
		DecryptString(EncryptedSystem32PathString, System32Path);
		RtlUnicodeStringCatString(&FullResolved, System32Path);
		RtlSecureZeroMemory(System32Path, decltype(EncryptedSystem32PathString)::Length);
#ifdef _WIN64
	}
#endif

	RtlUnicodeStringCat(&FullResolved, &FileName);

	if (NT_SUCCESS(RtlFileExists(&FullResolved)))
	{
		RtlxFreeUnicodeString(Resolved);

		*Resolved = FullResolved;
	}
	else
	{
		RtlxFreeUnicodeString(&FullResolved);

		Resolved->Length = 0;
	}

	return STATUS_SUCCESS;
}
