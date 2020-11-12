#pragma once

#include "MMInject.h"

#ifdef __cplusplus
extern "C" {
#endif

NTSTATUS
ProtectVAD(
	_In_ PEPROCESS Process,
	_In_ ULONG_PTR Address,
	_In_ ULONG Protection
	);

NTSTATUS
FindVAD(
	_In_ PEPROCESS Process,
	_In_ ULONG_PTR Address,
	_Out_ PMMVAD_SHORT *Result
	);

BOOLEAN
DoesVADConflict(
	_In_ PEPROCESS Process,
	_In_ ULONG_PTR StartingAddress,
	_In_ ULONG_PTR EndingAddress
	);

NTSTATUS
HideVAD(
	_In_ PEPROCESS Process,
	_In_ ULONG_PTR Address
	);

PMMPTE
GetPTEForVA(
	_In_ PVOID Address
	);

#ifdef __cplusplus
}
#endif
