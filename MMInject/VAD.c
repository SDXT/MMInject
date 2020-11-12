#include "MMInject.h"
#include "vad.h"
#include "BlackBone/VadHelpers.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ProtectVAD)
#pragma alloc_text(PAGE, FindVAD)
#pragma alloc_text(PAGE, HideVAD)
#pragma alloc_text(PAGE, DoesVADConflict)
#endif

extern DYNAMIC_DATA DynData;

ULONG MmProtectToValue[32] =
{
	PAGE_NOACCESS,
	PAGE_READONLY,
	PAGE_EXECUTE,
	PAGE_EXECUTE_READ,
	PAGE_READWRITE,
	PAGE_WRITECOPY,
	PAGE_EXECUTE_READWRITE,
	PAGE_EXECUTE_WRITECOPY,
	PAGE_NOACCESS,
	PAGE_NOCACHE | PAGE_READONLY,
	PAGE_NOCACHE | PAGE_EXECUTE,
	PAGE_NOCACHE | PAGE_EXECUTE_READ,
	PAGE_NOCACHE | PAGE_READWRITE,
	PAGE_NOCACHE | PAGE_WRITECOPY,
	PAGE_NOCACHE | PAGE_EXECUTE_READWRITE,
	PAGE_NOCACHE | PAGE_EXECUTE_WRITECOPY,
	PAGE_NOACCESS,
	PAGE_GUARD | PAGE_READONLY,
	PAGE_GUARD | PAGE_EXECUTE,
	PAGE_GUARD | PAGE_EXECUTE_READ,
	PAGE_GUARD | PAGE_READWRITE,
	PAGE_GUARD | PAGE_WRITECOPY,
	PAGE_GUARD | PAGE_EXECUTE_READWRITE,
	PAGE_GUARD | PAGE_EXECUTE_WRITECOPY,
	PAGE_NOACCESS,
	PAGE_WRITECOMBINE | PAGE_READONLY,
	PAGE_WRITECOMBINE | PAGE_EXECUTE,
	PAGE_WRITECOMBINE | PAGE_EXECUTE_READ,
	PAGE_WRITECOMBINE | PAGE_READWRITE,
	PAGE_WRITECOMBINE | PAGE_WRITECOPY,
	PAGE_WRITECOMBINE | PAGE_EXECUTE_READWRITE,
	PAGE_WRITECOMBINE | PAGE_EXECUTE_WRITECOPY
};

NTSTATUS
ProtectVAD(
	_In_ PEPROCESS Process,
	_In_ ULONG_PTR Address,
	_In_ ULONG Protection
	)
{
	PAGED_CODE();

	PMMVAD_SHORT VadShort = nullptr;
	const NTSTATUS Status = FindVAD(Process, Address, &VadShort);
	if (NT_SUCCESS(Status))
	{
#if NTDDI_VERSION >= NTDDI_WIN10
		const PMMVAD_SHORT_19H1 VadShort19H1 = reinterpret_cast<PMMVAD_SHORT_19H1>(VadShort);
		if (DynData.Version >= WINVER_10_19H1)
			VadShort19H1->u.VadFlags.Protection = Protection;
		else
			VadShort->u.VadFlags.Protection = Protection;
#else
		VadShort->u.VadFlags.Protection = Protection;
#endif
	}

	return Status;
}

NTSTATUS
FindVAD(
	_In_ PEPROCESS Process,
	_In_ ULONG_PTR Address,
	_Out_ PMMVAD_SHORT *Result
	)
{
	PAGED_CODE();

	const ULONG_PTR VpnStart = Address >> PAGE_SHIFT;
	const PMM_AVL_TABLE Table = reinterpret_cast<PMM_AVL_TABLE>(reinterpret_cast<PUCHAR>(Process) + DynData.VadRootOffset);
	PMM_AVL_NODE Node = GET_VAD_ROOT(Table);

	if (MiFindNodeOrParent(Table, VpnStart, &Node) == TableFoundNode)
	{
		*Result = reinterpret_cast<PMMVAD_SHORT>(Node);
		return STATUS_SUCCESS;
	}

	return STATUS_NOT_FOUND;
}

BOOLEAN
DoesVADConflict(
	_In_ PEPROCESS Process,
	_In_ ULONG_PTR StartingAddress,
	_In_ ULONG_PTR EndingAddress
	)
{
	PAGED_CODE();

	const ULONG_PTR StartVpn = StartingAddress >> PAGE_SHIFT;
	const ULONG_PTR EndVpn = EndingAddress >> PAGE_SHIFT;
	const PMM_AVL_TABLE Table = reinterpret_cast<PMM_AVL_TABLE>(reinterpret_cast<PUCHAR>(Process) + DynData.VadRootOffset);

	return MiCheckForConflictingVad(Table, StartVpn, EndVpn) != nullptr;
}

NTSTATUS
HideVAD(
	_In_ PEPROCESS Process,
	_In_ ULONG_PTR Address
	)
{
	PAGED_CODE();

	PMMVAD_SHORT VadShort = nullptr;
	const NTSTATUS Status = FindVAD(Process, Address, &VadShort);
	if (!NT_SUCCESS(Status))
		return Status;

#if NTDDI_VERSION >= NTDDI_WINBLUE
	RtlAvlRemoveNode(reinterpret_cast<PMM_AVL_TABLE>(reinterpret_cast<PUCHAR>(Process) + DynData.VadRootOffset), reinterpret_cast<PMMADDRESS_NODE>(VadShort));
#else
	MiRemoveNode(reinterpret_cast<PMMADDRESS_NODE>(VadShort), reinterpret_cast<PMM_AVL_TABLE>(reinterpret_cast<PUCHAR>(Process) + DynData.VadRootOffset));
#endif
	return STATUS_SUCCESS;
}

PMMPTE
GetPTEForVA(
	_In_ PVOID Address
	)
{
	if (DynData.Version >= WINVER_10_RS1)
	{
		const PMMPTE Pde = reinterpret_cast<PMMPTE>((((reinterpret_cast<ULONG_PTR>(Address) >> PDI_SHIFT) << PTE_SHIFT) & 0x3FFFFFF8ull) + DynData.DYN_PDE_BASE);
		if (Pde->u.Hard.LargePage)
			return Pde;

		return reinterpret_cast<PMMPTE>((((reinterpret_cast<ULONG_PTR>(Address) >> PTI_SHIFT) << PTE_SHIFT) & 0x7FFFFFFFF8ull) + DynData.DYN_PTE_BASE);
	}

	const PMMPTE Pde = MiGetPdeAddress(Address);
	if (Pde->u.Hard.LargePage)
		return Pde;

	return MiGetPteAddress(Address);
}
