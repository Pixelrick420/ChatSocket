#pragma once
#ifndef AES_H
#define AES_H

#include "sha256.h"
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

typedef struct
{
    char          roomName[64];
    unsigned char key[32];
    bool          hasKey;
} RoomEncryption;

#define ROOM_SALT_LEN      16
#define ROOM_SALT_HEX_SIZE (ROOM_SALT_LEN * 2 + 1)

void deriveKeyFromPassword(const char *password, unsigned char *key);
int encryptMessage(const unsigned char *plaintext, size_t plaintext_len,
                   const unsigned char *key, unsigned char *ciphertext);
int decryptMessage(const unsigned char *ciphertext, size_t ciphertext_len,
                   const unsigned char *key, unsigned char *plaintext);
void encodeBase64(const unsigned char *input, size_t length, char *output);
int decodeBase64(const char *input, unsigned char *output);
bool isEncryptedMessage(const char *buffer);
void bytesToHex(const unsigned char *input, size_t length, char *output);
bool hexToBytes(const char *input, unsigned char *output, size_t outputLen);
bool createRoomSecrets(const char *roomName, const char *password,
                       char saltHex[ROOM_SALT_HEX_SIZE],
                       char verifierHex[SHA256_HEX_SIZE],
                       unsigned char keyOut[32]);
bool verifyRoomSecret(const char *roomName, const char *password,
                      const char *saltHex,
                      char verifierHex[SHA256_HEX_SIZE],
                      unsigned char keyOut[32]);

#endif
