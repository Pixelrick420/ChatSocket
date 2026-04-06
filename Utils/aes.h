#pragma once
#ifndef AES_H
#define AES_H

#include "sha256.h"
#include <stddef.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

typedef struct
{
    char          roomName[64];
    unsigned char key[32];
    bool          hasKey;
} RoomEncryption;

void deriveKeyFromPassword(const char *password, unsigned char *key);
int encryptMessage(const unsigned char *plaintext, size_t plaintext_len,
                   const unsigned char *key, unsigned char *ciphertext);
int decryptMessage(const unsigned char *ciphertext, size_t ciphertext_len,
                   const unsigned char *key, unsigned char *plaintext);
void encodeBase64(const unsigned char *input, size_t length, char *output);
int decodeBase64(const char *input, unsigned char *output);
bool isEncryptedMessage(const char *buffer);

#endif
