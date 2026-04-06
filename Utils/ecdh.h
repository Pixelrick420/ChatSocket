#pragma once
#ifndef ECDH_H
#define ECDH_H

#include "identity.h"
#include <stdbool.h>

bool ecdhDeriveKey(const unsigned char myPrivX25519[32],
                   const unsigned char peerPubX25519[32],
                   unsigned char       keyOut[32]);
bool tokenToX25519PublicKey(const char *token, unsigned char x25519Out[32]);

#endif
