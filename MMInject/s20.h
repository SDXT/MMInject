#pragma once

enum s20_status_t
{
	S20_SUCCESS,
	S20_FAILURE
};

enum s20_keylen_t
{
	S20_KEYLEN_256,
	S20_KEYLEN_128
};


typedef UINT8 uint8_t;
typedef UINT16 uint16_t;
typedef UINT32 uint32_t;
typedef UINT64 uint64_t;

enum
s20_status_t
s20_crypt(
	uint8_t *key,
	enum s20_keylen_t keylen,
	uint8_t nonce[8],
	uint32_t si,
	uint8_t *buf,
	uint32_t buflen
	);
