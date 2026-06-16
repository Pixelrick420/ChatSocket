#pragma once
#ifndef TLS_H
#define TLS_H

#include "platform.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdbool.h>
#include <stddef.h>
#include <fcntl.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

SSL_CTX *tlsServerCtxCreate(void);
SSL *tlsServerAccept(SSL_CTX *ctx, SocketHandle fd);
SSL_CTX *tlsClientCtxCreate(void);
SSL *tlsClientConnect(SSL_CTX *ctx, SocketHandle fd);
bool tlsTrustOnFirstUse(SSL *ssl, const char *serverLabel);
bool tlsSend(SSL *ssl, const void *buf, size_t len);
ssize_t tlsRecv(SSL *ssl, char *buf, size_t maxLen);
void tlsFree(SSL *ssl);

#endif
