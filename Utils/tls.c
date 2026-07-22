#include "aes.h"
#include "tls.h"

#ifndef _WIN32
#include <sys/file.h>
#include <unistd.h>
#endif

static void tlsPrintErrors(const char *context) {
  fprintf(stderr, "tls: %s\n", context);
  ERR_print_errors_fp(stderr);
}

static const char *socketchatDir(void) {
  static char dir[512];
  if (dir[0])
    return dir;

  if (!platformGetConfigDir(dir, sizeof(dir)))
    return NULL;
  if (!platformEnsureDir(dir))
    return NULL;
  return dir;
}

static bool certPaths(char *certOut, size_t certSize, char *keyOut,
                      size_t keySize) {
  const char *dir = socketchatDir();
  if (!dir)
    return false;
  int n;

  n = snprintf(certOut, certSize, "%s/server.crt", dir);
  if (n < 0 || (size_t)n >= certSize)
    return false;

  n = snprintf(keyOut, keySize, "%s/server.key", dir);
  if (n < 0 || (size_t)n >= keySize)
    return false;

  return true;
}

static bool fingerprintPath(char *pathOut, size_t pathSize) {
  const char *dir = socketchatDir();
  if (!dir)
    return false;
  int n = snprintf(pathOut, pathSize, "%s%cknown_servers.tsv", dir,
                   SOCKETCHAT_PATH_SEP);
  return n >= 0 && (size_t)n < pathSize;
}

static bool certificateFingerprint(X509 *cert,
                                   char hexOut[SHA256_HEX_SIZE]) {
  if (!cert || !hexOut)
    return false;
  unsigned char digest[SHA256_BYTES_SIZE];
  unsigned int digestLen = 0;
  bool ok = X509_digest(cert, EVP_sha256(), digest, &digestLen) == 1 &&
            digestLen == SHA256_BYTES_SIZE;
  if (!ok)
    return false;

  bytesToHex(digest, digestLen, hexOut);
  return true;
}

bool tlsGetPeerFingerprint(SSL *ssl, char hexOut[SHA256_HEX_SIZE]) {
  X509 *cert = ssl ? SSL_get1_peer_certificate(ssl) : NULL;
  if (!cert)
    return false;
  bool ok = certificateFingerprint(cert, hexOut);
  X509_free(cert);
  return ok;
}

bool tlsGetLocalFingerprint(SSL *ssl, char hexOut[SHA256_HEX_SIZE]) {
  return ssl && certificateFingerprint(SSL_get_certificate(ssl), hexOut);
}

static bool generateSelfSignedCert(const char *certPath, const char *keyPath) {
  bool ok = false;
  EVP_PKEY *pkey = NULL;
  X509 *x509 = NULL;
  FILE *f = NULL;
  bool keyCreated = false;
  bool certCreated = false;

  EVP_PKEY_CTX *pkctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  if (!pkctx) {
    tlsPrintErrors("EVP_PKEY_CTX_new_id");
    goto out;
  }
  if (EVP_PKEY_keygen_init(pkctx) <= 0) {
    tlsPrintErrors("keygen_init");
    goto out;
  }
  if (EVP_PKEY_CTX_set_rsa_keygen_bits(pkctx, 2048) <= 0) {
    tlsPrintErrors("set_rsa_keygen_bits");
    goto out;
  }
  if (EVP_PKEY_keygen(pkctx, &pkey) <= 0) {
    tlsPrintErrors("keygen");
    goto out;
  }
  EVP_PKEY_CTX_free(pkctx);
  pkctx = NULL;

  x509 = X509_new();
  if (!x509) {
    tlsPrintErrors("X509_new");
    goto out;
  }

  ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
  X509_gmtime_adj(X509_get_notBefore(x509), 0);
  X509_gmtime_adj(X509_get_notAfter(x509), (long)60 * 60 * 24 * 365 * 10);
  X509_set_pubkey(x509, pkey);

  X509_NAME *name = X509_get_subject_name(x509);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                             (const unsigned char *)"SocketChat", -1, -1, 0);
  X509_set_issuer_name(x509, name);

  if (X509_sign(x509, pkey, EVP_sha256()) == 0) {
    tlsPrintErrors("X509_sign");
    goto out;
  }

  {
    int flags = O_WRONLY | O_CREAT | O_EXCL;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    int fd = open(keyPath, flags, 0600);
    if (fd < 0) {
      perror("tls: open server.key");
      goto out;
    }
    keyCreated = true;
    if (!platformSecureUserFileFd(fd)) {
      platformCloseFd(fd);
      goto out;
    }
    f = fdopen(fd, "w");
    if (!f) {
      perror("tls: fdopen server.key");
      platformCloseFd(fd);
      goto out;
    }
    if (!PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL)) {
      tlsPrintErrors("PEM_write_PrivateKey");
      fclose(f);
      f = NULL;
      goto out;
    }
    fclose(f);
    f = NULL;
  }

  {
    int flags = O_WRONLY | O_CREAT | O_EXCL;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    int fd = open(certPath, flags, 0600);
    if (fd < 0) {
      perror("tls: open server.crt");
      goto out;
    }
    certCreated = true;
    if (!platformSecureUserFileFd(fd)) {
      platformCloseFd(fd);
      goto out;
    }
    f = fdopen(fd, "w");
    if (!f)
      platformCloseFd(fd);
  }
  if (!f) {
    perror("tls: open server.crt");
    goto out;
  }
  if (!PEM_write_X509(f, x509)) {
    tlsPrintErrors("PEM_write_X509");
    goto out;
  }
  fclose(f);
  f = NULL;

  fprintf(stderr, "tls: generated self-signed certificate -> %s\n", certPath);
  ok = true;

out:
  if (f)
    fclose(f);
  if (x509)
    X509_free(x509);
  if (pkey)
    EVP_PKEY_free(pkey);
  if (pkctx)
    EVP_PKEY_CTX_free(pkctx);
  if (!ok) {
    if (certCreated)
      remove(certPath);
    if (keyCreated)
      remove(keyPath);
  }
  return ok;
}

static bool validateTlsFile(const char *path) {
  int flags = O_RDONLY;
#ifdef O_NOFOLLOW
  flags |= O_NOFOLLOW;
#endif
#ifdef O_NONBLOCK
  flags |= O_NONBLOCK;
#endif
  int fd = open(path, flags);
  if (fd < 0)
    return false;
  bool ok = platformSecureUserFileFd(fd);
  platformCloseFd(fd);
  return ok;
}

static X509 *loadCertificate(const char *path) {
  int flags = O_RDONLY;
#ifdef O_NOFOLLOW
  flags |= O_NOFOLLOW;
#endif
  int fd = open(path, flags);
  if (fd < 0 || !platformSecureUserFileFd(fd)) {
    if (fd >= 0)
      platformCloseFd(fd);
    return NULL;
  }
  FILE *file = fdopen(fd, "r");
  if (!file) {
    platformCloseFd(fd);
    return NULL;
  }
  X509 *certificate = PEM_read_X509(file, NULL, NULL, NULL);
  fclose(file);
  return certificate;
}

static EVP_PKEY *loadPrivateKey(const char *path) {
  int flags = O_RDONLY;
#ifdef O_NOFOLLOW
  flags |= O_NOFOLLOW;
#endif
  int fd = open(path, flags);
  if (fd < 0 || !platformSecureUserFileFd(fd)) {
    if (fd >= 0)
      platformCloseFd(fd);
    return NULL;
  }
  FILE *file = fdopen(fd, "r");
  if (!file) {
    platformCloseFd(fd);
    return NULL;
  }
  EVP_PKEY *key = PEM_read_PrivateKey(file, NULL, NULL, NULL);
  fclose(file);
  return key;
}

SSL_CTX *tlsServerCtxCreate(void) {
  char certPath[512], keyPath[512];
  if (!certPaths(certPath, sizeof(certPath), keyPath, sizeof(keyPath))) {
    fprintf(stderr, "tls: cannot determine cert paths\n");
    return NULL;
  }

  struct stat st;
  if (stat(certPath, &st) != 0 || stat(keyPath, &st) != 0) {
    if (!generateSelfSignedCert(certPath, keyPath))
      return NULL;
  }
  if (!validateTlsFile(certPath) || !validateTlsFile(keyPath)) {
    fprintf(stderr, "tls: certificate files must be owned regular files\n");
    return NULL;
  }

  const SSL_METHOD *method = TLS_server_method();
  SSL_CTX *ctx = SSL_CTX_new(method);
  if (!ctx) {
    tlsPrintErrors("SSL_CTX_new (server)");
    return NULL;
  }

  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

  SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);

  X509 *certificate = loadCertificate(certPath);
  EVP_PKEY *privateKey = loadPrivateKey(keyPath);
  if (!certificate || !privateKey) {
    tlsPrintErrors("load certificate material");
    X509_free(certificate);
    EVP_PKEY_free(privateKey);
    SSL_CTX_free(ctx);
    return NULL;
  }
  if (SSL_CTX_use_certificate(ctx, certificate) != 1 ||
      SSL_CTX_use_PrivateKey(ctx, privateKey) != 1) {
    tlsPrintErrors("install certificate material");
    X509_free(certificate);
    EVP_PKEY_free(privateKey);
    SSL_CTX_free(ctx);
    return NULL;
  }
  X509_free(certificate);
  EVP_PKEY_free(privateKey);
  if (SSL_CTX_check_private_key(ctx) != 1) {
    tlsPrintErrors("check_private_key");
    SSL_CTX_free(ctx);
    return NULL;
  }

  return ctx;
}

static int waitForSocket(SocketHandle fd, bool wantWrite, uint64_t deadlineMs) {
  for (;;) {
    fd_set readSet;
    fd_set writeSet;
    FD_ZERO(&readSet);
    FD_ZERO(&writeSet);
    FD_SET(fd, wantWrite ? &writeSet : &readSet);

    struct timeval timeout;
    struct timeval *timeoutPtr = NULL;
    if (deadlineMs > 0) {
      uint64_t now = platformMonotonicMs();
      if (now >= deadlineMs)
        return 0;
      uint64_t remaining = deadlineMs - now;
      timeout.tv_sec = (long)(remaining / 1000U);
      timeout.tv_usec = (int)((remaining % 1000U) * 1000U);
      timeoutPtr = &timeout;
    }

    int result = select((int)fd + 1, &readSet, &writeSet, NULL, timeoutPtr);
    if (result >= 0 || platformSocketErrno() != EINTR)
      return result;
  }
}

static SSL *tlsHandshake(SSL_CTX *ctx, SocketHandle fd, bool server,
                         unsigned int timeoutMs) {
  SSL *ssl = SSL_new(ctx);
  if (!ssl) {
    tlsPrintErrors(server ? "SSL_new (server)" : "SSL_new (client)");
    return NULL;
  }
  SSL_set_fd(ssl, (int)fd);

  if (!platformSetSocketNonBlocking(fd, true)) {
    tlsPrintErrors("set nonblocking handshake mode");
    SSL_free(ssl);
    return NULL;
  }

  uint64_t deadline = timeoutMs > 0 ? platformMonotonicMs() + timeoutMs : 0;
  bool connected = false;
  while (deadline == 0 || platformMonotonicMs() < deadline) {
    int result = server ? SSL_accept(ssl) : SSL_connect(ssl);
    if (result == 1) {
      connected = true;
      break;
    }
    int error = SSL_get_error(ssl, result);
    if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
      break;
    if (waitForSocket(fd, error == SSL_ERROR_WANT_WRITE, deadline) <= 0)
      break;
  }

  bool restored = platformSetSocketNonBlocking(fd, false);
  if (!connected || !restored) {
    if (!connected)
      tlsPrintErrors(server ? "SSL_accept" : "SSL_connect");
    else
      tlsPrintErrors("restore blocking socket mode");
    SSL_free(ssl);
    return NULL;
  }
  return ssl;
}

SSL *tlsServerAccept(SSL_CTX *ctx, SocketHandle fd, unsigned int timeoutMs) {
  return tlsHandshake(ctx, fd, true, timeoutMs);
}

SSL_CTX *tlsClientCtxCreate(void) {
  const SSL_METHOD *method = TLS_client_method();
  SSL_CTX *ctx = SSL_CTX_new(method);
  if (!ctx) {
    tlsPrintErrors("SSL_CTX_new (client)");
    return NULL;
  }

  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

  return ctx;
}

SSL *tlsClientConnect(SSL_CTX *ctx, SocketHandle fd, unsigned int timeoutMs) {
  return tlsHandshake(ctx, fd, false, timeoutMs);
}

bool tlsTrustOnFirstUse(SSL *ssl, const char *serverLabel) {
  if (!ssl || !serverLabel || !serverLabel[0])
    return false;
  for (size_t i = 0; serverLabel[i]; i++) {
    unsigned char ch = (unsigned char)serverLabel[i];
    if (ch < 0x21 || ch == 0x7f)
      return false;
  }

  char fingerprint[SHA256_HEX_SIZE];
  if (!tlsGetPeerFingerprint(ssl, fingerprint))
    return false;

  char path[512];
  if (!fingerprintPath(path, sizeof(path)))
    return false;

  int flags = O_RDWR | O_CREAT | O_APPEND;
#ifdef O_NOFOLLOW
  flags |= O_NOFOLLOW;
#endif
#ifdef O_NONBLOCK
  flags |= O_NONBLOCK;
#endif
  int fd = open(path, flags, 0600);
  if (fd < 0)
    return false;
  if (!platformSecureUserFileFd(fd)) {
    platformCloseFd(fd);
    return false;
  }

#ifndef _WIN32
  if (flock(fd, LOCK_EX) != 0) {
    platformCloseFd(fd);
    return false;
  }
#endif

  FILE *f = fdopen(fd, "a+");
  if (!f) {
    platformCloseFd(fd);
    return false;
  }
  if (fseek(f, 0, SEEK_SET) != 0) {
    fclose(f);
    return false;
  }

  char line[256];
  while (fgets(line, sizeof(line), f)) {
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
      line[--len] = '\0';
    char *tab = strchr(line, '\t');
    if (!tab)
      continue;
    *tab++ = '\0';
    if (strcmp(line, serverLabel) != 0)
      continue;

    unsigned char storedDigest[SHA256_BYTES_SIZE];
    bool validStoredPin = hexToBytes(tab, storedDigest, sizeof(storedDigest));
    OPENSSL_cleanse(storedDigest, sizeof(storedDigest));
    bool match = validStoredPin && strcmp(tab, fingerprint) == 0;
    if (!match) {
      if (validStoredPin) {
        fprintf(stderr,
                "tls: certificate pin mismatch for %s\n"
                "tls: pinned   %s\n"
                "tls: received %s\n",
                serverLabel, tab, fingerprint);
      } else {
        fprintf(stderr, "tls: stored certificate pin is invalid for %s\n",
                serverLabel);
      }
    }
    fclose(f);
    return match;
  }

  if (ferror(f) || fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return false;
  }

  if (fprintf(f, "%s\t%s\n", serverLabel, fingerprint) < 0 ||
      fflush(f) != 0) {
    fclose(f);
    return false;
  }
#ifndef _WIN32
  if (fsync(fd) != 0) {
    fclose(f);
    return false;
  }
#endif
  fclose(f);
  fprintf(stderr, "tls: pinned first-use certificate for %s: %s\n", serverLabel,
          fingerprint);
  return true;
}

bool tlsSend(SSL *ssl, const void *buf, size_t len) {
  if (!ssl || (!buf && len > 0))
    return false;
  int fd = SSL_get_fd(ssl);
  if (fd < 0 || !platformSetSocketNonBlocking((SocketHandle)fd, true))
    return false;
  uint64_t deadline = platformMonotonicMs() + 10000U;
  size_t written = 0;
  while (written < len) {
    int n = SSL_write(ssl, (const char *)buf + written, (int)(len - written));
    if (n > 0) {
      written += (size_t)n;
      continue;
    }
    int error = SSL_get_error(ssl, n);
    if ((error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) ||
        waitForSocket((SocketHandle)fd, error == SSL_ERROR_WANT_WRITE,
                      deadline) <= 0) {
      tlsPrintErrors("SSL_write");
      platformSetSocketNonBlocking((SocketHandle)fd, false);
      return false;
    }
  }
  return platformSetSocketNonBlocking((SocketHandle)fd, false);
}

ssize_t tlsRecv(SSL *ssl, char *buf, size_t maxLen) {
  return tlsRecvDeadline(ssl, buf, maxLen, 0);
}

int tlsReadByte(SSL *ssl, char *out) {
  if (!ssl || !out)
    return -1;
  int result = SSL_read(ssl, out, 1);
  if (result > 0)
    return 1;

  int error = SSL_get_error(ssl, result);
  if (error == SSL_ERROR_ZERO_RETURN)
    return 0;
  if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
    return TLS_READ_RETRY;
  if (error == SSL_ERROR_SYSCALL) {
    int socketError = platformSocketErrno();
    if (result == 0 && socketError == 0)
      return 0;
#ifdef _WIN32
    if (socketError == WSAEWOULDBLOCK || socketError == WSAEINTR)
#else
    if (socketError == EAGAIN || socketError == EWOULDBLOCK ||
        socketError == EINTR)
#endif
      return TLS_READ_RETRY;
  }
  tlsPrintErrors("SSL_read");
  return -1;
}

ssize_t tlsRecvDeadline(SSL *ssl, char *buf, size_t maxLen,
                        unsigned int timeoutMs) {
  if (maxLen < 2)
    return -1;

  int fd = SSL_get_fd(ssl);
  if (fd < 0 || !platformSetSocketNonBlocking((SocketHandle)fd, true))
    return -1;

  uint64_t deadline = timeoutMs > 0 ? platformMonotonicMs() + timeoutMs : 0;

  size_t offset = 0;
  while (offset < maxLen - 1) {
    char ch;
    int result = tlsReadByte(ssl, &ch);
    if (result > 0) {
      buf[offset++] = ch;
      if (ch == '\n')
        break;
      continue;
    }

    if (result == 0) {
      if (offset > 0) {
        platformSetSocketNonBlocking((SocketHandle)fd, false);
        return -1;
      }
      break;
    }
    if (result < 0 && result != TLS_READ_RETRY) {
      platformSetSocketNonBlocking((SocketHandle)fd, false);
      return -1;
    }
    if (waitForSocket((SocketHandle)fd, SSL_want_write(ssl), deadline) > 0)
      continue;
    if (deadline > 0 && platformMonotonicMs() >= deadline) {
      fprintf(stderr, "tls: frame deadline exceeded\n");
      platformSetSocketNonBlocking((SocketHandle)fd, false);
      return -1;
    }
    if (deadline == 0)
      continue;
    platformSetSocketNonBlocking((SocketHandle)fd, false);
    return -1;
  }

  if (!platformSetSocketNonBlocking((SocketHandle)fd, false))
    return -1;

  buf[offset] = '\0';
  if (offset == maxLen - 1 && offset > 0 && buf[offset - 1] != '\n') {
    fprintf(stderr, "tls: oversized frame rejected\n");
    return -1;
  }
  return offset == 0 ? 0 : (ssize_t)offset;
}

void tlsFree(SSL *ssl) {
  if (!ssl)
    return;
  SSL_shutdown(ssl);
  SSL_free(ssl);
}
