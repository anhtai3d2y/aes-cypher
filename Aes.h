#pragma once

#include <stdio.h>
#include <stdint.h>

#define AES_KEY_SIZE_128        16
#define AES_KEY_SIZE_192        24
#define AES_KEY_SIZE_256        32
#define AES_BLOCK_SIZE          16

typedef struct
{
    uint32_t    KeySizeInWords;
    uint32_t    NumberOfRounds;
    uint8_t     RoundKey[240];
} AesContext;

void AesInitialise128(uint8_t const Key [AES_KEY_SIZE_128], AesContext* Context);

void AesInitialise192(uint8_t const Key [AES_KEY_SIZE_192], AesContext* Context);

void AesInitialise256(uint8_t const Key [AES_KEY_SIZE_256], AesContext* Context);

void AesEncrypt(AesContext const* Context, uint8_t const Input [AES_BLOCK_SIZE], uint8_t Output [AES_BLOCK_SIZE]);

void AesDecrypt(AesContext const* Context, uint8_t const Input [AES_BLOCK_SIZE], uint8_t Output [AES_BLOCK_SIZE]);

void AesEncryptInPlace(AesContext const* Context, uint8_t Block [AES_BLOCK_SIZE]);

void AesDecryptInPlace(AesContext const* Context, uint8_t Block [AES_BLOCK_SIZE]);
