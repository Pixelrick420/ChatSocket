#include "tls.h"

static void tlsPrintErrors(const char *context) {
  fprintf(stderr, "tls: %s\n", context);
  ERR_print_errors_fp(stderr);
}

static const char *socketchatDir(void) {
  static char dir[512];
  if (dir[0])
    return dir;

  const char *home = getenv("HOME");
  if (!home) {
    struct passwd *pw = getpwuid(getuid());
    if (pw)
      home = pw->pw_dir;
  }
  if (!home)
    return NULL;

  snprintf(dir, sizeof(dir), "%s/.socketchat", home);
  if (mkdir(dir, 0700) != 0 && errno != EEXIST)
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

static bool generateSelfSignedCert(const char *certPath, const char *keyPath) {
  bool ok = false;
  EVP_PKEY *pkey = NULL;
  X509 *x509 = NULL;
  FILE *f = NULL;

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
    int fd = open(keyPath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
      perror("tls: open server.key");
      goto out;
    }
    f = fdopen(fd, "w");
    if (!f) {
      perror("tls: fdopen server.key");
      close(fd);
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

  f = fopen(certPath, "w");
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
  return ok;
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

  const SSL_METHOD *method = TLS_server_method();
  SSL_CTX *ctx = SSL_CTX_new(method);
  if (!ctx) {
    tlsPrintErrors("SSL_CTX_new (server)");
    return NULL;
  }

  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

  SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);

  if (SSL_CTX_use_certificate_file(ctx, certPath, SSL_FILETYPE_PEM) != 1) {
    tlsPrintErrors("use_certificate_file");
    SSL_CTX_free(ctx);
    return NULL;
  }
  if (SSL_CTX_use_PrivateKey_file(ctx, keyPath, SSL_FILETYPE_PEM) != 1) {
    tlsPrintErrors("use_PrivateKey_file");
    SSL_CTX_free(ctx);
    return NULL;
  }
  if (SSL_CTX_check_private_key(ctx) != 1) {
    tlsPrintErrors("check_private_key");
    SSL_CTX_free(ctx);
    return NULL;
  }

  return ctx;
}

SSL *tlsServerAccept(SSL_CTX *ctx, int fd) {
  SSL *ssl = SSL_new(ctx);
  if (!ssl) {
    tlsPrintErrors("SSL_new (server)");
    return NULL;
  }

  SSL_set_fd(ssl, fd);

  if (SSL_accept(ssl) != 1) {
    tlsPrintErrors("SSL_accept");
    SSL_free(ssl);
    return NULL;
  }
  return ssl;
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

SSL *tlsClientConnect(SSL_CTX *ctx, int fd) {
  SSL *ssl = SSL_new(ctx);
  if (!ssl) {
    tlsPrintErrors("SSL_new (client)");
    return NULL;
  }

  SSL_set_fd(ssl, fd);

  if (SSL_connect(ssl) != 1) {
    tlsPrintErrors("SSL_connect");
    SSL_free(ssl);
    return NULL;
  }
  return ssl;
}

bool tlsSend(SSL *ssl, const void *buf, size_t len) {
  size_t written = 0;
  while (written < len) {
    int n = SSL_write(ssl, (const char *)buf + written, (int)(len - written));
    if (n <= 0) {
      tlsPrintErrors("SSL_write");
      return false;
    }
    written += (size_t)n;
  }
  return true;
}

ssize_t tlsRecv(SSL *ssl, char *buf, size_t maxLen) {
  if (maxLen == 0)
    return -1;
  int n = SSL_read(ssl, buf, (int)(maxLen - 1));
  if (n > 0) {
    buf[n] = '\0';
    return (ssize_t)n;
  }
  int err = SSL_get_error(ssl, n);
  if (err == SSL_ERROR_ZERO_RETURN)
    return 0;
  if (err == SSL_ERROR_SYSCALL && errno == 0)
    return 0;
  if (err == SSL_ERROR_SSL)
    return 0;
  tlsPrintErrors("SSL_read");
  return -1;
}

void tlsFree(SSL *ssl) {
  if (!ssl)
    return;
  SSL_shutdown(ssl);
  SSL_free(ssl);
}
