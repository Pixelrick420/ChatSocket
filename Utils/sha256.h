#pragma once
#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SHA256_HEX_SIZE   65
#define SHA256_BYTES_SIZE 32
#define HASH_ITERATIONS 50000
#define SALT_LEN        16
#define SALT_HEX_SIZE   (SALT_LEN * 2 + 1)

typedef struct sha256
{
    uint32_t state[8];
    uint8_t  buffer[64];
    uint64_t n_bits;
    uint8_t  buffer_counter;
} sha256_t;

void sha256Init        (sha256_t *sha);
void sha256Append      (sha256_t *sha, const void *data, size_t n_bytes);
void sha256FinalizeHex  (sha256_t *sha, char *dst_hex65);
void sha256FinalizeBytes(sha256_t *sha, void *dst_bytes32);
void sha256Hex  (const void *src, size_t n_bytes, char *dst_hex65);
void sha256Bytes(const void *src, size_t n_bytes, void *dst_bytes32);
char *createHashedPass(const char *roomName, const char *password);
int verifyHashedPass(const char *stored, const char *roomName,
                     const char *password);
int verifyHashedPassPrehashed(const char *stored, const char *roomName,
                               const char *passwordSha256Hex);

#endif
