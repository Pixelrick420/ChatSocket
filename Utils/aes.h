#ifndef AES_H
#define AES_H

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <string.h>
#include "sha256.h"

typedef struct
{
    char roomName[64];
    unsigned char key[32];
    bool hasKey;
} RoomEncryption;

int decodeBase64(const char *input, unsigned char *output);
void encodeBase64(const unsigned char *input, size_t length, char *output);
int decryptMessage(const unsigned char *ciphertext, size_t ciphertext_len, const unsigned char *key, unsigned char *plaintext);
int encryptMessage(const unsigned char *plaintext, size_t plaintext_len, const unsigned char *key, unsigned char *ciphertext);
bool isEncryptedMessage(const char *buffer);
void deriveKeyFromPassword(const char *password, unsigned char *key);

#endif