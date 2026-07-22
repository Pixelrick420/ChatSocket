#pragma once
#ifndef ECDH_H
#define ECDH_H

#include <stdbool.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <stdio.h>
#include <string.h>

bool x25519GenerateKeypair(unsigned char pubOut[32], unsigned char privOut[32]);
bool ecdhDeriveSessionKey(const unsigned char myPrivX25519[32],
                          const unsigned char peerPubX25519[32],
                          const char *initiatorToken,
                          const char *responderToken,
                          const char *sessionId,
                          const unsigned char initiatorPub[32],
                          const unsigned char responderPub[32],
                          unsigned char keyOut[32]);

#endif
