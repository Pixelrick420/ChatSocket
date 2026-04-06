#pragma once
#ifndef IDENTITY_H
#define IDENTITY_H

#include <stdbool.h>
#include <stddef.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define IDENTITY_KEY_BYTES   32
#define TOKEN_HEX_LEN        64
#define TOKEN_STR_SIZE       65
#define SIG_BYTES            64
#define SIG_HEX_LEN         128
#define SIG_HEX_SIZE        129
#define CHALLENGE_BYTES      32
#define CHALLENGE_HEX_LEN    64
#define CHALLENGE_HEX_SIZE   65

typedef struct {
    unsigned char priv[IDENTITY_KEY_BYTES];
    unsigned char pub[IDENTITY_KEY_BYTES];
    char          token[TOKEN_STR_SIZE];
} Identity;


bool identityLoadOrCreate(Identity *id);
bool identitySign(const Identity        *id,
                  const unsigned char   *msg,
                  size_t                 msgLen,
                  unsigned char          sigOut[SIG_BYTES]);
bool identityVerify(const char          *pubHex,
                    const unsigned char *msg,
                    size_t               msgLen,
                    const unsigned char  sig[SIG_BYTES]);
bool identityEd25519PubToX25519(const unsigned char ed25519Pub[IDENTITY_KEY_BYTES],
                                unsigned char       x25519Out[IDENTITY_KEY_BYTES]);
bool identityEd25519PrivToX25519(const unsigned char ed25519Priv[IDENTITY_KEY_BYTES],
                                 unsigned char       x25519Out[IDENTITY_KEY_BYTES]);
void identityPrintToken(const Identity *id);

#endif
