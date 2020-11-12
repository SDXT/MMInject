#pragma once

#ifdef __cplusplus
extern "C" {
#endif

PVOID
FindModule(
	_In_ PEPROCESS Process,
	_In_ PUNICODE_STRING ModuleName
	);

PVOID
GetModuleExport(
	_In_ PVOID Base,
	_In_ PCCHAR NameOrOrdinal,
	_In_ PEPROCESS Process
	);

NTSTATUS
ResolveImagePath(
	_In_ PEPROCESS Process,
	_In_ PUNICODE_STRING Path,
	_Inout_ PUNICODE_STRING Resolved
	);

#ifdef __cplusplus
}
#endif
