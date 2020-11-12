#include "MMInject.h"
#include "StringEncryptor.h"
#include "vad.h"
#include "BlackBone/Loader.h"
#include "Utils.h"

	static
	BOOLEAN
	NTAPI
	HandleEnumerationCallback(
	#if NTDDI_VERSION > NTDDI_WIN7
		_In_ PHANDLE_TABLE HandleTable,
	#endif
		_Inout_ PHANDLE_TABLE_ENTRY HandleTableEntry,
		_In_ HANDLE Handle,
		_In_ PVOID EnumParameter
		);

	static
	NTSTATUS
	SetCSRSSWindowStation(
		_In_ PEPROCESS Process,
		_Out_ PBOOLEAN ProcessIsCsrss
		);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, HandleEnumerationCallback)
#pragma alloc_text(PAGE, SetCSRSSWindowStation)
#pragma alloc_text(PAGE, StartDllThread)
#pragma alloc_text(PAGE, InjectDll)
#endif

CONSTEXPR UCHAR DllInitializer64[] =
{
	
	0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,		// mov rax, gs:[30h]
	0xBE, 0xF7, 0xFF, 0x00, 0x00,								// mov esi, 0FFF7h
	0x66, 0x21, 0xB0, 0xEE, 0x17, 0x00, 0x00,					// and [rax+17EEh], si

	0x40, 0x53,						// push rbx
	0x48, 0x83, 0xEC, 0x20,			// sub rsp, 20h
	0x4C, 0x8B, 0x41, 0x18,			// mov r8, [rcx+18h]
	0x48, 0x8B, 0xD9,				// mov rbx, rcx
	0x8B, 0x51, 0x10,				// mov edx, [rcx+10h]
	0x48, 0x8B, 0x49, 0x08,			// mov rcx, [rcx+8]
	0x48, 0x85, 0xC9,				// test rcx, rcx
	0x74, 0x02,						// jz +2
	0xFF, 0x13,						// call [rbx]
	0x48, 0x8B, 0x4B, 0x18,			// mov rcx, [rbx+18h]
	0x45, 0x33, 0xC0,				// xor r8d, r8d	
	0xBA, 0x01, 0x00, 0x00, 0x00,	// mov edx, 1
	0x48, 0x8B, 0x43, 0x20,			// mov rax, [rbx+20h]
	0x48, 0x83, 0xC4, 0x20,			// add rsp, 20h
	0x5B,							// pop rbx
	0x48, 0xFF, 0xE0				// jmp rax
};

CONSTEXPR UCHAR DllInitializer32[] =
{
	0x64, 0xA1, 0x18, 0x00, 0x00, 0x00,							// mov eax, fs:[18h]
	0xB9, 0xF7, 0xFF, 0x00, 0x00,								// mov ecx, 0FFF7h
	0x66, 0x21, 0x88, 0xCA, 0x0F, 0x00, 0x00,					// and [eax+0FCAh], cx

	0x8B, 0x44, 0x24, 0x04,			// mov eax, [esp+4h]
	0x6A, 0x00,						// push 0
	0x6A, 0x01,						// push 1
	0xFF, 0x70, 0x18,				// push [eax+18h]
	0xFF, 0x75, 0xF4,				// push [ebp-0Ch]			
	0xFF, 0x60, 0x20				// jmp [eax+20h]
};

typedef struct _DLL_INIT_DATA
{
	PVOID RtlAddFunctionTable;
	PRUNTIME_FUNCTION FunctionTable;
	ULONG EntryCount;
	PVOID ImageBase;
	PVOID EntryPoint;
	UCHAR InitFunction[sizeof(DllInitializer64)];
} DLL_INIT_DATA, *PDLL_INIT_DATA;

typedef struct _ENUM_HANDLES_CONTEXT
{
	ULONG NormalAccessBits;
	ULONG DesiredAccessBits;
	HANDLE Handle;
} ENUM_HANDLES_CONTEXT, *PENUM_HANDLES_CONTEXT;

extern ULONG MmProtectToValue[32];
extern DYNAMIC_DATA DynData;
extern t_NtCreateThreadEx NtCreateThreadEx;
extern t_NtResumeThread NtResumeThread;
extern t_NtTerminateThread NtTerminateThread;
extern t_NtProtectVirtualMemory NtProtectVirtualMemory;

PVOID RegionBase = nullptr, MappedPages = nullptr;
PMDL Mdl = nullptr;

static
NTSTATUS
AllocatePhysicalMemory(
	_In_ PVOID *RequestedBaseAddress,
	_In_ SIZE_T Size,
	_In_ ULONG Protection
	)
{
	PVOID BaseAddress = PAGE_ALIGN(*RequestedBaseAddress);
	*RequestedBaseAddress = nullptr;
	Size = ADDRESS_AND_SIZE_TO_SPAN_PAGES(BaseAddress, Size) << PAGE_SHIFT;

	RegionBase = ExAllocatePoolWithTag(NonPagedPoolNx, Size, GetPoolTag());
	if (RegionBase == nullptr)
		return STATUS_NO_MEMORY;

	RtlZeroMemory(RegionBase, Size);

	Mdl = IoAllocateMdl(RegionBase, static_cast<ULONG>(Size), FALSE, FALSE, nullptr);
	if (Mdl == nullptr)
	{
		ExFreePool(RegionBase);
		return STATUS_NO_MEMORY;
	}

	MmBuildMdlForNonPagedPool(Mdl);

	__try
	{
		*RequestedBaseAddress = MmMapLockedPagesSpecifyCache(Mdl,
															UserMode,
															MmCached,
															BaseAddress,
															FALSE,
															NormalPagePriority | MdlMappingNoExecute);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) { }

	if (*RequestedBaseAddress == nullptr)
	{
		__try
		{
			*RequestedBaseAddress = MmMapLockedPagesSpecifyCache(Mdl,
																UserMode,
																MmCached,
																nullptr,
																FALSE,
																NormalPagePriority | MdlMappingNoExecute);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) { }
	}

	if (*RequestedBaseAddress == nullptr)
	{
		IoFreeMdl(Mdl);
		ExFreePool(RegionBase);
		return STATUS_NONE_MAPPED;
	}

	MappedPages = *RequestedBaseAddress;
	const ULONG_PTR FinalBaseAddress = reinterpret_cast<ULONG_PTR>(MappedPages);
	ProtectVAD(PsGetCurrentProcess(), FinalBaseAddress, MmProtectToValue[Protection]);

	if ((Protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0)
	{
		for (ULONG_PTR pAddress = FinalBaseAddress; pAddress < FinalBaseAddress + Size; pAddress += PAGE_SIZE)
		{
			GetPTEForVA(reinterpret_cast<PVOID>(pAddress))->u.Hard.NoExecute = 0;
		}
	}

	return STATUS_SUCCESS;
}

static
BOOLEAN
HandleEnumerationCallback(
#if NTDDI_VERSION > NTDDI_WIN7
	_In_ PHANDLE_TABLE HandleTable,
#endif
	_Inout_ PHANDLE_TABLE_ENTRY HandleTableEntry,
	_In_ HANDLE Handle,
	_In_ PVOID EnumParameter
	)
{
	PAGED_CODE();

	const PENUM_HANDLES_CONTEXT Context = static_cast<PENUM_HANDLES_CONTEXT>(EnumParameter);
	BOOLEAN Result = FALSE;

	if (HandleTableEntry->GrantedAccessBits == Context->DesiredAccessBits)
	{
		Context->Handle = Handle;
		Result = TRUE;
	}
	else if (HandleTableEntry->GrantedAccessBits == Context->NormalAccessBits)
	{
		HandleTableEntry->GrantedAccessBits = Context->DesiredAccessBits;
		Printf("Upgraded access mask of handle %02X from 0x%04X to 0x%04X.\n",
			HandleToULong(Handle), Context->NormalAccessBits, Context->DesiredAccessBits);

		Context->Handle = Handle;
		Result = TRUE;
	}

#if NTDDI_VERSION > NTDDI_WIN7
	_InterlockedExchangeAdd8(reinterpret_cast<PCHAR>(&HandleTableEntry->VolatileLowValue), 1);
	if (HandleTable != nullptr && HandleTable->HandleContentionEvent != 0)
		ExfUnblockPushLock(&HandleTable->HandleContentionEvent, nullptr);
#endif

	return Result;
}

static
NTSTATUS
SetCSRSSWindowStation(
	_In_ PEPROCESS Process,
	_Out_ PBOOLEAN ProcessIsCsrss
	)
{
	PAGED_CODE();

	*ProcessIsCsrss = FALSE;

	const PCHAR ProcessFileName = PsGetProcessImageFileName(Process);
	if (ProcessFileName == nullptr ||
		ProcessFileName[0] != 'c' || ProcessFileName[1] != 's' || ProcessFileName[2] != 'r' ||
		ProcessFileName[3] != 's' || ProcessFileName[4] != 's' || ProcessFileName[5] != '.' ||
		ProcessFileName[6] != 'e' || ProcessFileName[7] != 'x' || ProcessFileName[8] != 'e')
		return STATUS_SUCCESS;

	*ProcessIsCsrss = TRUE;

	const NTSTATUS Status = PsAcquireProcessExitSynchronization(Process);
	if (!NT_SUCCESS(Status))
		return Status;
	const PHANDLE_TABLE HandleTable = *reinterpret_cast<PHANDLE_TABLE*>(reinterpret_cast<PUCHAR>(Process) +
		DynData.ObjectTableOffset);
	if (HandleTable == nullptr)
	{
		PsReleaseProcessExitSynchronization(Process);
		return STATUS_NOT_FOUND;
	}

	ENUM_HANDLES_CONTEXT Context;
	Context.NormalAccessBits = (READ_CONTROL | DELETE | WRITE_DAC | WRITE_OWNER |
								0x1 /*WINSTA_ENUMDESKTOPS*/ | 0x2 /*WINSTA_READATTRIBUTES*/);	// 0xF0003
	Context.DesiredAccessBits = (READ_CONTROL | DELETE | WRITE_DAC | WRITE_OWNER |
								0x37F /*WINSTA_ALL_ACCESS*/);									// 0xF037F
	Context.Handle = nullptr;

	const BOOLEAN Found = ExEnumHandleTable(HandleTable,
										reinterpret_cast<PEX_ENUM_HANDLE_CALLBACK>(HandleEnumerationCallback),
										&Context,
										nullptr);

	PsReleaseProcessExitSynchronization(Process);

	if (!Found)
	{
		Printf("Could not find a useable window station handle in the CSRSS process handle table.\n");
		return STATUS_NOT_FOUND;
	}

	
	return STATUS_SUCCESS;
}

VOID
GetThreadStartName(
	_Out_ PANSI_STRING ThreadStartName
	)
{
	RtlZeroMemory(ThreadStartName->Buffer, ThreadStartName->MaximumLength);
	ThreadStartName->Length = 0;

	CONSTEXPR const ULONG NumThreadStartNames = 8;
	const ULONG Index = RtlNextRandom(0, NumThreadStartNames);
	NT_ASSERT(Index <= NumThreadStartNames - 1);

	switch (Index)
	{
		case 0:
		{
			DecryptString(EncryptedEtwpCreateEtwThreadString, ThreadStartName->Buffer);
			ThreadStartName->Length = decltype(EncryptedEtwpCreateEtwThreadString)::Length - sizeof(CHAR);
			break;
		}
		case 1:
		{
			DecryptString(EncryptedRtlActivateActivationContextExString, ThreadStartName->Buffer);
			ThreadStartName->Length = decltype(EncryptedRtlActivateActivationContextExString)::Length - sizeof(CHAR);
			break;
		}
		case 2:
		{
			DecryptString(EncryptedRtlCreateActivationContextString, ThreadStartName->Buffer);
			ThreadStartName->Length = decltype(EncryptedRtlCreateActivationContextString)::Length - sizeof(CHAR);
			break;
		}
		case 3:
		{
			DecryptString(EncryptedRtlQueryActivationContextApplicationSettingsString, ThreadStartName->Buffer);
			ThreadStartName->Length = decltype(EncryptedRtlQueryActivationContextApplicationSettingsString)::Length - sizeof(CHAR);
			break;
		}
		case 4:
		{
			DecryptString(EncryptedRtlValidateHeapString, ThreadStartName->Buffer);
			ThreadStartName->Length = decltype(EncryptedRtlValidateHeapString)::Length - sizeof(CHAR);
			break;
		}
		case 5:
		{
			DecryptString(EncryptedTpStartAsyncIoOperationString, ThreadStartName->Buffer);
			ThreadStartName->Length = decltype(EncryptedTpStartAsyncIoOperationString)::Length - sizeof(CHAR);
			break;
		}
		case 6:
		{
			DecryptString(EncryptedTpWaitForWorkString, ThreadStartName->Buffer);
			ThreadStartName->Length = decltype(EncryptedTpWaitForWorkString)::Length - sizeof(CHAR);
			break;
		}
		case 7:
		{
			DecryptString(EncryptedWinSqmEventWriteString, ThreadStartName->Buffer);
			ThreadStartName->Length = decltype(EncryptedWinSqmEventWriteString)::Length - sizeof(CHAR);
			break;
		}
		default:
			NT_ASSERT(FALSE);
			break;
	}
}

NTSTATUS
StartDllThread(
	_In_ PVOID ImageBase,
	_In_ ULONG EntryPointRva,
	_In_ BOOLEAN IsWow64
	)
{
	PAGED_CODE();

	PDLL_INIT_DATA DllInitData = nullptr;
	SIZE_T DllInitDataSize = sizeof(*DllInitData);
	PCONTEXT Context = nullptr;
	NTSTATUS Status;

	ULONG FunctionTableSize = 0;
	const PIMAGE_RUNTIME_FUNCTION_ENTRY ExceptionDirectory = !IsWow64 ? static_cast<PIMAGE_RUNTIME_FUNCTION_ENTRY>(
		RtlpImageDirectoryEntryToDataEx(ImageBase,
										TRUE,
										IMAGE_DIRECTORY_ENTRY_EXCEPTION,
										&FunctionTableSize))
		: nullptr;

	
	WCHAR NtdllNameBuffer[decltype(EncryptedNtdllString)::Length];
	DecryptString(EncryptedNtdllString, NtdllNameBuffer);
	UNICODE_STRING NtdllName = { decltype(EncryptedNtdllString)::Length - sizeof(WCHAR), decltype(EncryptedNtdllString)::Length, NtdllNameBuffer };
	const PVOID Ntdll = FindModule(PsGetCurrentProcess(), &NtdllName);

	CHAR RtlAddFunctionTableName[decltype(EncryptedRtlAddFunctionTableString)::Length];
	DecryptString(EncryptedRtlAddFunctionTableString, RtlAddFunctionTableName);
	const PVOID RtlAddFunctionTable = !IsWow64
									? GetModuleExport(Ntdll,
										RtlAddFunctionTableName,
										PsGetCurrentProcess())
									: nullptr;

	CHAR ThreadStartNameBuffer[128];
	ANSI_STRING ThreadStartName = { 0, sizeof(ThreadStartNameBuffer), ThreadStartNameBuffer };
	GetThreadStartName(&ThreadStartName);
	const PVOID ThreadStartRoutine = GetModuleExport(Ntdll,
													ThreadStartName.Buffer,
													PsGetCurrentProcess());

	RtlSecureZeroMemory(NtdllNameBuffer, decltype(EncryptedNtdllString)::Length);
	RtlSecureZeroMemory(RtlAddFunctionTableName, decltype(EncryptedRtlAddFunctionTableString)::Length);
	if ((!IsWow64 && RtlAddFunctionTable == nullptr) || ThreadStartRoutine == nullptr)
	{
		Printf("Failed to find required ntdll.dll exports RtlAddFunctionTable and/or %Z.\n", &ThreadStartName);
		Status = STATUS_PROCEDURE_NOT_FOUND;
		goto finished;
	}

	Status = NtAllocateVirtualMemory(NtCurrentProcess(),
									reinterpret_cast<PVOID*>(&DllInitData),
									0,
									&DllInitDataSize,
									MEM_COMMIT | MEM_RESERVE,
									PAGE_READWRITE);
	if (!NT_SUCCESS(Status))
	{
		Printf("NtAllocateVirtualMemory (DLL init data): %08X\n", Status);
		goto finished;
	}

	SIZE_T ContextSize = IsWow64 ? sizeof(WOW64_CONTEXT) : sizeof(CONTEXT);
	Status = NtAllocateVirtualMemory(NtCurrentProcess(),
									reinterpret_cast<PVOID*>(&Context),
									0,
									&ContextSize,
									MEM_COMMIT | MEM_RESERVE,
									PAGE_READWRITE);
	if (!NT_SUCCESS(Status))
	{
		Printf("NtAllocateVirtualMemory (context): %08X\n", Status);
		goto finished;
	}

	DllInitData->RtlAddFunctionTable = RtlAddFunctionTable;
	DllInitData->FunctionTable = reinterpret_cast<PRUNTIME_FUNCTION>(ExceptionDirectory);
	DllInitData->EntryCount = FunctionTableSize / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
	DllInitData->ImageBase = ImageBase;
	DllInitData->EntryPoint = static_cast<PUCHAR>(ImageBase) + EntryPointRva;
	RtlCopyMemory(DllInitData->InitFunction, IsWow64 ? DllInitializer32 : DllInitializer64,
		IsWow64 ? sizeof(DllInitializer32) : sizeof(DllInitializer64));

	if (IsWow64)
	{
		NT_ASSERT(DllInitData->InitFunction[31] == 0xF4);
		if (DynData.Version < WINVER_10_19H1)
		{
			DllInitData->InitFunction[31] = 0xF8;
		}
	}

	ULONG OldProtect;
	Status = NtProtectVirtualMemory(NtCurrentProcess(),
									reinterpret_cast<PVOID*>(&DllInitData),
									&DllInitDataSize,
									PAGE_EXECUTE,
									&OldProtect);
	if (!NT_SUCCESS(Status))
	{
		Printf("NtProtectVirtualMemory: %08X\n", Status);
		goto finished;
	}

	constexpr SIZE_T NumAttributes = 1;
	constexpr SIZE_T AttributesSize = sizeof(SIZE_T) + NumAttributes * sizeof(PS_ATTRIBUTE);
	PS_ATTRIBUTE_LIST AttributeList;
	RtlZeroMemory(&AttributeList, AttributesSize);
	AttributeList.TotalLength = AttributesSize;

	CLIENT_ID ClientId;
	RtlZeroMemory(&ClientId, sizeof(ClientId));
	AttributeList.Attributes[0].Attribute = PS_ATTRIBUTE_CLIENT_ID;
	AttributeList.Attributes[0].Size = sizeof(ClientId);
	AttributeList.Attributes[0].Value = reinterpret_cast<ULONG_PTR>(&ClientId);

	Printf("Creating thread with fake entry point 0x%p (ntdll!%Z).\n", ThreadStartRoutine, &ThreadStartName);
	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes,
								nullptr,
								IsWow64 ? 0 : OBJ_KERNEL_HANDLE,
								nullptr,
								nullptr);

	const ULONG PspNotifyEnableMask = *DynData.pPspNotifyEnableMask;
	*DynData.pPspNotifyEnableMask = 0;

	HANDLE ThreadHandle;
	Status = NtCreateThreadEx(&ThreadHandle,
							THREAD_ALL_ACCESS,
							&ObjectAttributes,
							NtCurrentProcess(),
							reinterpret_cast<PUSER_THREAD_START_ROUTINE>(ThreadStartRoutine),
							DllInitData,
							THREAD_CREATE_FLAGS_CREATE_SUSPENDED |
							(DynData.Version <= WINVER_7_SP1 ? 0 : THREAD_CREATE_FLAGS_SUPPRESS_DLLMAINS),
							0,
							0,
							0,
							&AttributeList);

	*DynData.pPspNotifyEnableMask |= PspNotifyEnableMask;

	if (!NT_SUCCESS(Status))
	{
		Printf("NtCreateThreadEx: %08X\n", Status);
		goto finished;
	}

	InitializeStackCookie(ImageBase, &ClientId);

	if (IsWow64)
	{
		const KPROCESSOR_MODE PreviousMode = KeSetPreviousMode(UserMode);
		PWOW64_CONTEXT Wow64Context = reinterpret_cast<PWOW64_CONTEXT>(Context);
		RtlZeroMemory(Wow64Context, sizeof(*Wow64Context));
		Wow64Context->ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;

		Status = NtQueryInformationThread(ThreadHandle,
										ThreadWow64Context,
										Wow64Context,
										sizeof(*Wow64Context),
										nullptr);
		if (NT_SUCCESS(Status))
		{
			Wow64Context->Eax = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(static_cast<PVOID>(DllInitData->InitFunction)));

			Status = NtSetInformationThread(ThreadHandle,
											ThreadWow64Context,
											Wow64Context,
											sizeof(*Wow64Context));
			if (NT_SUCCESS(Status))
				Printf("Updated WOW64 thread context. Entry point: 0x%p, DllMain: 0x%p.\n",
					reinterpret_cast<PVOID>(DllInitData->InitFunction), DllInitData->EntryPoint);
		}

		KeSetPreviousMode(PreviousMode);
	}
	else
	{
		PETHREAD Thread = nullptr;
		Status = ObReferenceObjectByHandleWithTag(ThreadHandle,
												THREAD_ALL_ACCESS,
												*PsThreadType,
												KernelMode,
												GetPoolTag(),
												reinterpret_cast<PVOID*>(&Thread),
												nullptr);
		if (NT_SUCCESS(Status))
		{
			RtlZeroMemory(Context, sizeof(*Context));
			Context->ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;

			Status = PsGetContextThread(Thread, Context, UserMode);
			if (NT_SUCCESS(Status))
			{
#ifdef _M_AMD64
				Context->Rcx = reinterpret_cast<ULONG64>(static_cast<PVOID>(DllInitData->InitFunction));
#else
				Context->Eax = static_cast<ULONG>(reinterpret_cast<ULONG64>(static_cast<PVOID>(DllInitData->InitFunction)));
#endif

				Status = PsSetContextThread(Thread, Context, UserMode);
				if (NT_SUCCESS(Status))
					Printf("Updated thread context. Entry point: 0x%p, DllMain: 0x%p.\n",
						reinterpret_cast<PVOID>(DllInitData->InitFunction), DllInitData->EntryPoint);
			}
			ObfDereferenceObject(Thread);
		}
	}

	if (!NT_SUCCESS(Status))
	{
		Printf("Failed to set %s thread context: %08X\n", IsWow64 ? "WOW64" : "", Status);
		NtTerminateThread(ThreadHandle, Status);
		Printf("Thread terminated.\n");
	}
	else
	{
		NtResumeThread(ThreadHandle, nullptr);
		Printf("Thread resumed.\n");
	}

	ObCloseHandle(ThreadHandle, static_cast<KPROCESSOR_MODE>(IsWow64 ? UserMode : KernelMode));

	RtlSleep(250);

	__try
	{
		ProbeForWrite(ImageBase, sizeof(PVOID), alignof(PVOID));
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		Printf("Process died! Returning immediately without cleanup.\n");
		return STATUS_PROCESS_IS_TERMINATING;
	}

finished:
	if (Context != nullptr)
	{
		RtlFillGarbageMemory(Context, sizeof(*Context));
		ContextSize = 0;
		NtFreeVirtualMemory(NtCurrentProcess(),
							reinterpret_cast<PVOID*>(&Context),
							&ContextSize,
							MEM_RELEASE);
	}
	if (DllInitData != nullptr)
	{
		if (NT_SUCCESS(NtProtectVirtualMemory(NtCurrentProcess(),
											reinterpret_cast<PVOID*>(&DllInitData),
											&DllInitDataSize,
											PAGE_READWRITE,
											&OldProtect)))
		{
			RtlFillGarbageMemory(DllInitData, sizeof(*DllInitData));
		}
		DllInitDataSize = 0;
		NtFreeVirtualMemory(NtCurrentProcess(),
							reinterpret_cast<PVOID*>(&DllInitData),
							&DllInitDataSize,
							MEM_RELEASE);
	}

	return Status;
}

NTSTATUS
InjectDll(
	_In_opt_ ULONG ProcessId,
	_In_opt_ PUNICODE_STRING ProcessName,
	_In_opt_ BOOLEAN WaitForNamedProcess,
	_In_ PUNICODE_STRING DllNtPath,
	_In_ BOOLEAN DeleteDll,
	_In_ BOOLEAN WipeImageHeaders
	)
{
	PAGED_CODE();
	
	PEPROCESS Process = nullptr;
	PEPROCESS_FLAGS2 Flags2 = nullptr;
	PEPROCESS_MITIGATION_FLAGS MitigationFlags = nullptr;
	UCHAR DisableDynamicCode = 0, RestrictSetThreadContext = 0;
	NTSTATUS Status;

	if (ProcessId != 0)
	{
		Printf("Opening process with PID %u...\n", ProcessId);
		Status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &Process);
	}
	else
	{
		Printf("Opening process %wZ...\n", ProcessName);
		Status = OpenSessionProcess(&Process,
									ProcessName,
									1,
									WaitForNamedProcess);
	}

	if (!NT_SUCCESS(Status))
	{
		if (Status == STATUS_INVALID_CID)
			Printf("Process with PID %u not found.\n", ProcessId);
		else if (Status != STATUS_CANCELLED)
			Printf("%s error %08X\n", (ProcessId != 0 ? "PsLookupProcessByProcessId" : "OpenSessionProcess"), Status);
		return Status;
	}
	else
		Printf("Process with PID %u found.\n", Process);

	if (Process != nullptr && PsGetProcessDebugPort(Process) != nullptr)
	{
		
		Printf("If you're reading this message, it means you're an idiot and got defeated by your own anti-debug check. Recompile and try again\n");
		ObfDereferenceObject(Process);
		return STATUS_SUCCESS;
	}

#ifdef _M_AMD64
	const BOOLEAN IsWow64 = PsGetProcessWow64Process(Process) != nullptr;
#else
	constexpr const BOOLEAN IsWow64 = FALSE;
#endif

	if (DynData.Version >= WINVER_81)
	{
		UCHAR CfgEnabled;
		Flags2 = reinterpret_cast<PEPROCESS_FLAGS2>(reinterpret_cast<PUCHAR>(Process) + DynData.EProcessFlags2Offset);
		if (DynData.Version <= WINVER_10_RS2)
		{
			CONST PEPROCESS_FLAGS Flags = reinterpret_cast<PEPROCESS_FLAGS>(reinterpret_cast<PUCHAR>(Process) + DynData.EProcessFlagsOffset);
			CfgEnabled = Flags->ControlFlowGuardEnabled;
			DisableDynamicCode = Flags2->DisableDynamicCode;
		}
		else
		{
			MitigationFlags = reinterpret_cast<PEPROCESS_MITIGATION_FLAGS>(reinterpret_cast<PUCHAR>(Process) + DynData.MitigationFlagsOffset);
			CfgEnabled = MitigationFlags->ControlFlowGuardEnabled;
			DisableDynamicCode = MitigationFlags->DisableDynamicCode;

			if (DynData.Version >= WINVER_10_RS4)
			{
				RestrictSetThreadContext = reinterpret_cast<PEPROCESS_FLAGS2_RS4_PLUS>(Flags2)->RestrictSetThreadContext;
			}
		}

		Printf("Process prohibits dynamic code execution? %s\n", DisableDynamicCode ? "YES. Removing..." : "no");
		if (DisableDynamicCode)
		{
			if (DynData.Version <= WINVER_10_RS2)
				Flags2->DisableDynamicCode = 0;
			else
				MitigationFlags->DisableDynamicCode = 0;
			Printf("\tRestriction removed.\n");
		}

		Printf("Process has Control Flow Guard? %s\n", CfgEnabled ? "YES. Patching..." : "no");
		if (CfgEnabled)
		{
			Status = PatchGuardCFCheckFunctionPointers(Process);
			Printf("%s\n", (NT_SUCCESS(Status)
				? "\tSuccesfully patched CFG guard check pointers."
				: "\tError: failed to patch CFG guard check pointers."));
			if (!NT_SUCCESS(Status))
				return Status;
		}
		
		Printf("Process restricts SetThreadContext? %s\n", RestrictSetThreadContext ? "YES. Handling it..." : "no");
		if (RestrictSetThreadContext)
		{
			reinterpret_cast<PEPROCESS_FLAGS2_RS4_PLUS>(Flags2)->RestrictSetThreadContext = 0;
			Printf("\tRestriction removed. Note that (un)setting RestrictSetThreadContext is *untested* because there is currently no documented interface and even system processes do not use it\n");
		}
	}

	bool Attached = false;
	Printf("Injecting %ls...\n", DllNtPath->Buffer + 4);

	PUCHAR EncryptedDllMemory = nullptr, DecryptedDllMemory = nullptr;
	SIZE_T EncryptedDllFileSize = 0, DecryptedDllFileSize = 0;
	Status = RtlReadFileToBytes(DllNtPath,
								&EncryptedDllMemory,
								&EncryptedDllFileSize);
	if (!NT_SUCCESS(Status))
		goto finished;

	if (DeleteDll)
	{
		Printf("Deleting DLL file... \n");
		OBJECT_ATTRIBUTES ObjectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(DllNtPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE);
		Status = NtDeleteFile(&ObjectAttributes);
		if (!NT_SUCCESS(Status))
		{
			Printf("failure (NtDeleteFile error %08X). Aborting injection.\n", Status);
			goto finished;
		}
		Printf("done.\n");
	}

	PIMAGE_NT_HEADERS NtHeaders;
	Status = DecryptPeFile(EncryptedDllMemory,
							EncryptedDllFileSize,
							&DecryptedDllMemory,
							&DecryptedDllFileSize,
							&NtHeaders);
	if (!NT_SUCCESS(Status))
	{
		Printf("Failed to decrypt DLL file: 0x%08X\n", Status);
		goto finished;
	}

	if ((IsWow64 && NtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) ||
		(!IsWow64 && NtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64))
	{
		Printf("Error: wrong executable bitness (%u) for host process (%u).\n",
			NtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 ? 32 : 64,
			IsWow64 ? 32 : 64);
		Status = STATUS_INVALID_IMAGE_FORMAT;
		goto finished;
	}

	const PVOID HeadersImageBase = reinterpret_cast<PVOID>(HEADER_FIELD(NtHeaders, ImageBase));
	const SIZE_T HeadersSizeOfHeaders = static_cast<SIZE_T>(HEADER_FIELD(NtHeaders, SizeOfHeaders));
	SIZE_T HeadersSizeOfImage = static_cast<SIZE_T>(HEADER_FIELD(NtHeaders, SizeOfImage));
	const ULONG HeadersAddressOfEntryPoint = static_cast<ULONG>(HEADER_FIELD(NtHeaders, AddressOfEntryPoint));
	const PIMAGE_SECTION_HEADER SectionHeaders = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<PUCHAR>(NtHeaders) +
		sizeof(ULONG) + sizeof(IMAGE_FILE_HEADER) + NtHeaders->FileHeader.SizeOfOptionalHeader);

	BOOLEAN ProcessIsCsrss;
	Status = SetCSRSSWindowStation(Process, &ProcessIsCsrss);
	if (!NT_SUCCESS(Status))
		goto finished;

	if (!ProcessIsCsrss)
	{
		
		Status = RtlAdjustProcessPrivilege(Process,
										SE_LOAD_DRIVER_PRIVILEGE,
										TRUE);
		if (!NT_SUCCESS(Status))
		{
			Printf("Failed to enable SeLoadDriverPrivilege for target process: 0x%08X\n", Status);
			goto finished;
		}
	}

	const PVOID RandomisedImageBase = RandomiseSystemImageBase(Process, NtHeaders);
	PVOID RemoteImageBase = RandomisedImageBase;

	KAPC_STATE ApcState;
	KeStackAttachProcess(Process, &ApcState);
	Attached = true;

	BOOLEAN AllocatedPhysical = TRUE;
	Status = AllocatePhysicalMemory(&RemoteImageBase,
									HeadersSizeOfImage,
									PAGE_READWRITE);
	if (!NT_SUCCESS(Status))
	{
		AllocatedPhysical = FALSE;
		RemoteImageBase = RandomisedImageBase;
		Status = NtAllocateVirtualMemory(NtCurrentProcess(),
										&RemoteImageBase,
										0,
										&HeadersSizeOfImage,
										MEM_COMMIT | MEM_RESERVE,
										PAGE_READWRITE);
		if (Status == STATUS_CONFLICTING_ADDRESSES)
		{
			RemoteImageBase = nullptr;
			Status = NtAllocateVirtualMemory(NtCurrentProcess(),
											&RemoteImageBase,
											0,
											&HeadersSizeOfImage,
											MEM_COMMIT | MEM_RESERVE,
											PAGE_READWRITE);
		}
		if (!NT_SUCCESS(Status))
		{
			Printf("NtAllocateVirtualMemory: %08X\n", Status);
			goto finished;
		}
	}
	Printf("Allocated 0x%X bytes of %s memory in process at 0x%p.\n",
		static_cast<ULONG>(HeadersSizeOfImage), (AllocatedPhysical ? "PHYSICAL" : "VIRTUAL"), RemoteImageBase);

	if (RemoteImageBase != HeadersImageBase)
	{
		Printf("Relocating image from 0x%p to 0x%p...\n", HeadersImageBase, RemoteImageBase);
		Status = LdrRelocateImageData(DecryptedDllMemory, RemoteImageBase);
		if (!NT_SUCCESS(Status))
		{
			Printf("Failed to relocate image: %08X\n", Status);
			goto finished;
		}

		const PULONG_PTR ImageBaseRva = reinterpret_cast<PULONG_PTR>(IMAGE64(NtHeaders)
			? reinterpret_cast<ULONG_PTR>(&reinterpret_cast<PIMAGE_NT_HEADERS32>(NtHeaders)->OptionalHeader.ImageBase)
			: reinterpret_cast<ULONG_PTR>(&NtHeaders->OptionalHeader.ImageBase));
		if (IMAGE64(NtHeaders))
			*ImageBaseRva = reinterpret_cast<ULONG_PTR>(RemoteImageBase);
		else
			*reinterpret_cast<PULONG>(ImageBaseRva) = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(RemoteImageBase));
	}

	__try
	{
		RtlCopyMemory(RemoteImageBase, DecryptedDllMemory, HeadersSizeOfHeaders);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		Status = GetExceptionCode();
		Printf("RtlCopyMemory exception %08X\n", Status);
		goto finished;
	}

	ULONG OldProtect;
	if (!WipeImageHeaders)
	{
		if (AllocatedPhysical)
		{
			const PMMPTE PTE = GetPTEForVA(reinterpret_cast<PVOID>(RemoteImageBase));
			PTE->u.Hard.Dirty1 = PTE->u.Hard.Write = 0;
			PTE->u.Hard.NoExecute = 1;
		}
		else
		{
			PVOID HeaderPage = RemoteImageBase;
			SIZE_T HeaderSize = HeadersSizeOfHeaders;
			Status = NtProtectVirtualMemory(NtCurrentProcess(),
											&HeaderPage,
											&HeaderSize,
											PAGE_READONLY,
											&OldProtect);
			if (!NT_SUCCESS(Status))
			{
				Printf("NtProtectVirtualMemory (PE headers): %08X\n", Status);
				goto finished;
			}
		}
	}

	for (ULONG i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++)
	{
		if (!(SectionHeaders[i].Characteristics & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)) ||
			SectionHeaders[i].PointerToRawData == 0)
			continue;

		const PVOID SectionVa = static_cast<PVOID>(static_cast<PUCHAR>(RemoteImageBase) + SectionHeaders[i].VirtualAddress);
		const PVOID SectionData = static_cast<PVOID>(DecryptedDllMemory + SectionHeaders[i].PointerToRawData);

		__try
		{
			RtlCopyMemory(SectionVa, SectionData, SectionHeaders[i].SizeOfRawData);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			Status = GetExceptionCode();
			Printf("RtlCopyMemory (section %u/%u): exception %08X\n",
				(i + 1), NtHeaders->FileHeader.NumberOfSections, Status);
			goto finished;
		}
	}
	Printf("Wrote %u PE sections to process.\n\n", NtHeaders->FileHeader.NumberOfSections);

	Status = ResolveImports(Process, RemoteImageBase, TRUE);
	if (!NT_SUCCESS(Status))
	{
		Printf("Failed to resolve imports for module; error %08X.\n", Status);
		goto finished;
	}

	Printf("Successfully resolved imports for module. \n", Status);

	if (AllocatedPhysical)
	{
		Status = ProtectVAD(Process, reinterpret_cast<ULONG_PTR>(RemoteImageBase), MM_READWRITE);
		if (!NT_SUCCESS(Status))
		{
			Printf("Failed to change VAD protection to MM_READWRITE; error %08X.\n", Status);
			goto finished;
		}
		Printf("Changed VAD protection to MM_READWRITE.\n");
	}

	for (ULONG i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++)
	{
		if (!(SectionHeaders[i].Characteristics & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)) ||
			SectionHeaders[i].PointerToRawData == 0)
			continue;

		ULONG Characteristics = SectionHeaders[i].Characteristics;
		if ((Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0)
			Characteristics |= IMAGE_SCN_MEM_WRITE;

		const ULONG Protection = CharacteristicsToPageProtection(Characteristics);
		SIZE_T SectionVirtualSize = SectionHeaders[i].Misc.VirtualSize > 0
			? SectionHeaders[i].Misc.VirtualSize
			: SectionHeaders[i].SizeOfRawData;
		PVOID SectionVa = static_cast<PVOID>(static_cast<PUCHAR>(RemoteImageBase) + SectionHeaders[i].VirtualAddress);

		if (AllocatedPhysical)
		{
			SectionVa = reinterpret_cast<PVOID>(ROUND_TO_PAGES(SectionVa));

			for (ULONG_PTR Address = reinterpret_cast<ULONG_PTR>(SectionVa);
				Address < reinterpret_cast<ULONG_PTR>(SectionVa) + SectionVirtualSize;
				Address += PAGE_SIZE)
			{
				const PMMPTE PTE = GetPTEForVA(reinterpret_cast<PVOID>(Address));
				if ((Characteristics & IMAGE_SCN_MEM_WRITE) == 0)
					PTE->u.Hard.Dirty1 = PTE->u.Hard.Write = 0;
				if ((Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
					PTE->u.Hard.NoExecute = 0;
				else
					PTE->u.Hard.NoExecute = 1;
			}
		}
		else if (Protection != PAGE_NOACCESS)
		{
			Status = NtProtectVirtualMemory(NtCurrentProcess(),
											&SectionVa,
											&SectionVirtualSize,
											Protection,
											&OldProtect);
			if (!NT_SUCCESS(Status))
			{
				Printf("NtProtectVirtualMemory (section %u/%u): %08X\n",
					(i + 1), NtHeaders->FileHeader.NumberOfSections, Status);
				goto finished;
			}
		}
		else
		{
			NtFreeVirtualMemory(NtCurrentProcess(),
								&SectionVa,
								&SectionVirtualSize,
								MEM_DECOMMIT);
		}
	}

	Status = StartDllThread(RemoteImageBase,
							HeadersAddressOfEntryPoint,
							IsWow64);
	if (!NT_SUCCESS(Status))
		goto finished;

	WipeImageSections(RemoteImageBase,
						AllocatedPhysical,
						SectionHeaders,
						WipeImageHeaders);

finished:
	if (Attached)
		KeUnstackDetachProcess(&ApcState);

	if (DecryptedDllMemory != nullptr)
	{
		RtlFillGarbageMemory(DecryptedDllMemory, DecryptedDllFileSize);
		ExFreePool(DecryptedDllMemory);
	}

	if (EncryptedDllMemory != nullptr)
	{
		RtlFillGarbageMemory(EncryptedDllMemory, EncryptedDllFileSize);
		ExFreePool(EncryptedDllMemory);
	}

	if (DynData.Version >= WINVER_10_RS4 && RestrictSetThreadContext)
	{
		reinterpret_cast<PEPROCESS_FLAGS2_RS4_PLUS>(Flags2)->RestrictSetThreadContext = 1;
		Printf("Restored SetThreadContext restriction.\n");
	}

	if (DynData.Version >= WINVER_81 && DisableDynamicCode)
	{
		if (DynData.Version <= WINVER_10_RS2)
			Flags2->DisableDynamicCode = 1;
		else
			MitigationFlags->DisableDynamicCode = 1;
		Printf("Restored dynamic code restriction.\n");
	}

	if (Process != nullptr)
		ObfDereferenceObject(Process);

	if (NT_SUCCESS(Status))
		Printf("DLL injection successful.\n");

	return Status;
}
