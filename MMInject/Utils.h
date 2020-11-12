#pragma once

#include "MMInject.h"

#ifdef __cplusplus
extern "C" {
#endif

ULONG
RtlNextRandom(
	_In_ ULONG Min,
	_In_ ULONG Max
	);

VOID
RtlFillGarbageMemory(
	_In_ PVOID Destination,
	_In_ SIZE_T Size
	);

ULONG
GetPoolTag(
	);

NTSTATUS
RtlFuckingCopyMemory(
	_In_ PVOID Destination,
	_In_ CONST VOID* Source,
	_In_ ULONG Length
	);

NTSTATUS
RtlAdjustProcessPrivilege(
	_In_ PEPROCESS Process,
	_In_ ULONG Privilege,
	_In_ BOOLEAN Enable
	);

NTSTATUS
RegQueryValueString(
	_In_ PWSTR KeyNameBuffer,
	_In_ PWSTR ValueNameBuffer,
	_Inout_ PUNICODE_STRING ValueString
	);

NTSTATUS
RegQueryValueBoolean(
	_In_ PWSTR KeyNameBuffer,
	_In_ PWSTR ValueNameBuffer,
	_Out_ PBOOLEAN Value
	);

BOOLEAN
RtlUnicodeStringEndsIn(
	_In_ PCUNICODE_STRING String,
	_In_ PCUNICODE_STRING Substring
	);

NTSTATUS
RtlStripPath(
	_In_ PUNICODE_STRING Path,
	_Out_ PUNICODE_STRING Name
	);

NTSTATUS
RtlStripFilename(
	_In_ PUNICODE_STRING Path,
	_Out_ PUNICODE_STRING Directory
	);

NTSTATUS
RtlFileExists(
	_In_ PUNICODE_STRING NtPath
	);

inline
VOID
RtlxInitAnsiString(
	_Out_ PANSI_STRING DestinationString,
	_In_opt_ PCSZ SourceString
	)
{
	DestinationString->Buffer = const_cast<PCHAR>(SourceString);
	if (SourceString == nullptr)
	{
		DestinationString->Length = 0;
		DestinationString->MaximumLength = 0;
	}
	else
	{
		const USHORT Length = static_cast<USHORT>(strlen(SourceString));
		DestinationString->Length = Length;
		DestinationString->MaximumLength = Length + sizeof('\0');
	}
}

inline
VOID
RtlxInitUnicodeString(
	_Out_ PUNICODE_STRING DestinationString,
	_In_opt_ PCWSTR SourceString
	)
{
	DestinationString->Buffer = const_cast<PWSTR>(SourceString);
	if (SourceString == nullptr)
	{
		DestinationString->Length = 0;
		DestinationString->MaximumLength = 0;
	}
	else
	{
		const USHORT Length = static_cast<USHORT>(wcslen(SourceString) * sizeof(WCHAR));
		DestinationString->Length = Length;
		DestinationString->MaximumLength = Length + sizeof(UNICODE_NULL);
	}
}

inline
VOID
RtlxFreeUnicodeString(
	_Inout_ PUNICODE_STRING UnicodeString
	)
{
	if (UnicodeString->Buffer != nullptr)
	{
		ExFreePool(UnicodeString->Buffer);
		RtlZeroMemory(UnicodeString, sizeof(*UnicodeString));
	}
}

inline
VOID
RtlxCopyUnicodeString(
	_Out_ PUNICODE_STRING DestinationString,
	_In_opt_ PCUNICODE_STRING SourceString
	)
{
	if (SourceString == nullptr)
	{
		DestinationString->Length = 0;
		return;
	}

	const PWCHAR Src = SourceString->Buffer;
	const PWCHAR Dst = DestinationString->Buffer;
	ULONG N = SourceString->Length;
	if (static_cast<USHORT>(N) > DestinationString->MaximumLength)
	{
		N = DestinationString->MaximumLength;
	}

	DestinationString->Length = static_cast<USHORT>(N);
	RtlCopyMemory(Dst, Src, N);
	if ((DestinationString->Length + sizeof (WCHAR)) <= DestinationString->MaximumLength)
	{
		Dst[N / sizeof(WCHAR)] = UNICODE_NULL;
	}
}

#ifdef __cplusplus
}
#endif
