#include "MMInject.h"
#include "Utils.h"
#include "StringEncryptor.h"
#include <bcrypt.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, DecryptPeFile)
#endif

#define BLOCK_SIZE		128
#define KEY_SIZE		128

static const UCHAR SecretKey[] =
{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

NTSTATUS
DecryptPeFile(
	_In_ PUCHAR EncryptedDllBuffer,
	_In_ SIZE_T EncryptedDllSize,
	_Out_ PUCHAR *DecryptedDllBuffer,
	_Out_ PSIZE_T DecryptedDllSize,
	_Out_ PIMAGE_NT_HEADERS *NtHeaders
	)
{
	PAGED_CODE();

	*DecryptedDllBuffer = nullptr;
	*DecryptedDllSize = 0;
	*NtHeaders = nullptr;

	const PIMAGE_NT_HEADERS Headers = RtlpImageNtHeaderEx(EncryptedDllBuffer, EncryptedDllSize);
	if (Headers != nullptr)
	{
		*DecryptedDllBuffer = static_cast<PUCHAR>(ExAllocatePoolWithTag(NonPagedPoolNx, EncryptedDllSize, GetPoolTag()));
		if (*DecryptedDllBuffer == nullptr)
			return STATUS_NO_MEMORY;

		RtlCopyMemory(*DecryptedDllBuffer, EncryptedDllBuffer, EncryptedDllSize);
		*DecryptedDllSize = EncryptedDllSize;
		*NtHeaders = Headers;

		return STATUS_SUCCESS;
	}

	const ULONG BlockLength = BLOCK_SIZE / CHAR_BIT;
	BCRYPT_ALG_HANDLE AlgorithmHandle = nullptr;
	BCRYPT_KEY_HANDLE KeyHandle = nullptr;
	PUCHAR KeyObject = nullptr, PaddedPlaintextBuffer = nullptr;
	ULONG KeyObjectLength = 0, PaddedPlaintextLength = 0;
	UCHAR Iv[BLOCK_SIZE / CHAR_BIT];

	WCHAR AESName[decltype(EncryptedAESString)::Length];
	WCHAR BlockLengthName[decltype(EncryptedBlockLengthString)::Length];
	WCHAR ChainingModeName[decltype(EncryptedChainingModeString)::Length];
	WCHAR ChainingModeCBCName[decltype(EncryptedChainingModeCBCString)::Length];
	WCHAR ObjectLengthName[decltype(EncryptedObjectLengthString)::Length];
	DecryptString(EncryptedAESString, AESName);
	DecryptString(EncryptedBlockLengthString, BlockLengthName);
	DecryptString(EncryptedChainingModeString, ChainingModeName);
	DecryptString(EncryptedChainingModeCBCString, ChainingModeCBCName);
	DecryptString(EncryptedObjectLengthString, ObjectLengthName);

	NTSTATUS Status = BCryptOpenAlgorithmProvider(&AlgorithmHandle,
												AESName,
												nullptr,
												BCRYPT_PROV_DISPATCH);
	if (!NT_SUCCESS(Status))
	{
		Printf("BCryptOpenAlgorithmProvider: error 0x%08X\n", Status);
		goto Exit;
	}

	ULONG BlockLengthCheck, ResultSize;
	Status = BCryptGetProperty(AlgorithmHandle,
								BlockLengthName,
								reinterpret_cast<PUCHAR>(&BlockLengthCheck),
								sizeof(BlockLengthCheck),
								&ResultSize,
								0);
	if (!NT_SUCCESS(Status))
	{
		Printf("BCryptGetProperty(BCRYPT_BLOCK_LENGTH): error 0x%08X\n", Status);
		goto Exit;
	}
	if (BlockLengthCheck != BlockLength)
	{
		Printf("BCryptGetProperty(BCRYPT_BLOCK_LENGTH) returned %u bytes; expected %u.\n", BlockLengthCheck, BlockLength);
		goto Exit;
	}

	Status = BCryptSetProperty(AlgorithmHandle,
								ChainingModeName, 
								reinterpret_cast<PUCHAR>(ChainingModeCBCName),
								sizeof(BCRYPT_CHAIN_MODE_CBC),
								0);
	if (!NT_SUCCESS(Status))
	{
		Printf("BCryptSetProperty(BCRYPT_CHAINING_MODE): error 0x%08X\n", Status);
		goto Exit;
	}

	Status = BCryptGetProperty(AlgorithmHandle,
								ObjectLengthName,
								reinterpret_cast<PUCHAR>(&KeyObjectLength),
								sizeof(KeyObjectLength),
								&ResultSize,
								0);
	if (!NT_SUCCESS(Status))
	{
		Printf("BCryptGetProperty(BCRYPT_OBJECT_LENGTH): error 0x%08X\n", Status);
		goto Exit;
	}

	KeyObject = static_cast<PUCHAR>(ExAllocatePoolWithTag(NonPagedPoolNx, KeyObjectLength, GetPoolTag()));
	RtlZeroMemory(KeyObject, KeyObjectLength);

	Status = BCryptGenerateSymmetricKey(AlgorithmHandle,
										&KeyHandle,
										KeyObject,
										KeyObjectLength,
										const_cast<PUCHAR>(SecretKey),
										sizeof(SecretKey),
										0);
	if (!NT_SUCCESS(Status))
	{
		Printf("BCryptGenerateSymmetricKey: error 0x%08X\n", Status);
		goto Exit;
	}

	Status = BCryptDecrypt(KeyHandle,
							EncryptedDllBuffer,
							static_cast<ULONG>(EncryptedDllSize),
							nullptr,
							Iv,
							BlockLength,
							nullptr,
							0,
							&PaddedPlaintextLength,
							BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(Status))
	{
		Printf("BCryptDecrypt (1): error 0x%08X\n", Status);
		goto Exit;
	}

	const ULONG PlaintextLength = PaddedPlaintextLength - BlockLength;
	PaddedPlaintextBuffer = static_cast<PUCHAR>(ExAllocatePoolWithTag(NonPagedPoolNx, PaddedPlaintextLength, GetPoolTag()));
	const PUCHAR PlaintextBuffer = static_cast<PUCHAR>(ExAllocatePoolWithTag(NonPagedPoolNx, PlaintextLength, GetPoolTag()));
	if (PaddedPlaintextBuffer == nullptr || PlaintextBuffer == nullptr)
	{
		Status = STATUS_NO_MEMORY;
		goto Exit;
	}
	RtlZeroMemory(PaddedPlaintextBuffer, PaddedPlaintextLength);
	RtlZeroMemory(PlaintextBuffer, PlaintextLength);

	Status = BCryptDecrypt(KeyHandle,
							EncryptedDllBuffer,
							static_cast<ULONG>(EncryptedDllSize),
							nullptr,
							Iv,
							BlockLength,
							PaddedPlaintextBuffer,
							PlaintextLength + BlockLength,
							&PaddedPlaintextLength,
							BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(Status))
	{
		Printf("BCryptDecrypt (2): error 0x%08X\n", Status);
		goto Exit;
	}

	RtlCopyMemory(PlaintextBuffer, PaddedPlaintextBuffer + BlockLength, PlaintextLength);

	*DecryptedDllBuffer = PlaintextBuffer;
	*DecryptedDllSize = PlaintextLength;
	*NtHeaders = RtlpImageNtHeaderEx(PlaintextBuffer, PlaintextLength);

	if (*NtHeaders == nullptr)
	{
		Printf("Decrypted buffer is not a valid PE file!\n");
		Status = STATUS_INVALID_IMAGE_NOT_MZ;
		goto Exit;
	}

	Status = STATUS_SUCCESS;

Exit:
	RtlSecureZeroMemory(AESName, decltype(EncryptedAESString)::Length);
	RtlSecureZeroMemory(BlockLengthName, decltype(EncryptedBlockLengthString)::Length);
	RtlSecureZeroMemory(ChainingModeName, decltype(EncryptedChainingModeString)::Length);
	RtlSecureZeroMemory(ChainingModeCBCName, decltype(EncryptedChainingModeCBCString)::Length);
	RtlSecureZeroMemory(ObjectLengthName, decltype(EncryptedObjectLengthString)::Length);

	if (AlgorithmHandle != nullptr)
	{
		BCryptCloseAlgorithmProvider(AlgorithmHandle, 0);
	}

	if (KeyHandle != nullptr)
	{
		BCryptDestroyKey(KeyHandle);
	}

	if (KeyObject != nullptr)
	{
		RtlSecureZeroMemory(KeyObject, KeyObjectLength);
		ExFreePool(KeyObject);
	}

	if (PaddedPlaintextBuffer != nullptr)
	{
		RtlSecureZeroMemory(PaddedPlaintextBuffer, PaddedPlaintextLength);
		ExFreePool(PaddedPlaintextBuffer);
	}

	return Status;
}
