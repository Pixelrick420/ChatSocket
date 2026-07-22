#pragma once
#ifndef IDENTITY_H
#define IDENTITY_H

#include "platform.h"

#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IDENTITY_KEY_BYTES   32
#define TOKEN_HEX_LEN        64
#define TOKEN_STR_SIZE       65
#define SIG_BYTES            64
#define SIG_HEX_LEN         128
#define SIG_HEX_SIZE        129
#define CHALLENGE_BYTES      32
#define CHALLENGE_HEX_LEN    64
#define CHALLENGE_HEX_SIZE   65
#define MAX_NAME_LEN         64
#define MAX_DM_NICKS         50

typedef struct {
    unsigned char priv[IDENTITY_KEY_BYTES];
    unsigned char pub[IDENTITY_KEY_BYTES];
    char          token[TOKEN_STR_SIZE];
} Identity;

typedef struct {
    char token[TOKEN_STR_SIZE];
    char nick[MAX_NAME_LEN];
} DmNickEntry;


bool identityLoadOrCreate(Identity *id);
bool identitySign(const Identity        *id,
                  const unsigned char   *msg,
                  size_t                 msgLen,
                  unsigned char          sigOut[SIG_BYTES]);
bool identityVerify(const char          *pubHex,
                    const unsigned char *msg,
                    size_t               msgLen,
                    const unsigned char  sig[SIG_BYTES]);
void identityPrintToken(const Identity *id);
bool identityLoadUsername(char *username, size_t maxLen);
bool identitySaveUsername(const char *username);
size_t identityLoadDmNickEntries(DmNickEntry *entries, size_t maxEntries);
bool identitySaveDmNickEntries(const DmNickEntry *entries, size_t count);

#endif
