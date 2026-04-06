#include "identity.h"

static void bytesToHex(const unsigned char *bytes, size_t len, char *out) {
  static const char hex[] = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    out[i * 2] = hex[bytes[i] >> 4];
    out[i * 2 + 1] = hex[bytes[i] & 0x0f];
  }
  out[len * 2] = '\0';
}

static int hexNibble(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

static bool hexToBytes(const char *hex, size_t hexLen, unsigned char *out,
                       size_t outLen) {
  if (hexLen != outLen * 2)
    return false;
  for (size_t i = 0; i < outLen; i++) {
    int hi = hexNibble(hex[i * 2]);
    int lo = hexNibble(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0)
      return false;
    out[i] = (unsigned char)((hi << 4) | lo);
  }
  return true;
}

static char *identityFilePath(void) {
  const char *home = getenv("HOME");
  if (!home) {
    struct passwd *pw = getpwuid(getuid());
    if (pw)
      home = pw->pw_dir;
  }
  if (!home) {
    fprintf(stderr, "identity: cannot determine HOME directory\n");
    return NULL;
  }

  char dirPath[512];
  snprintf(dirPath, sizeof(dirPath), "%s/.socketchat", home);
  if (mkdir(dirPath, 0700) != 0 && errno != EEXIST) {
    perror("identity: mkdir ~/.socketchat");
    return NULL;
  }

  char *path = malloc(512);
  if (!path)
    return NULL;
  snprintf(path, 512, "%s/.socketchat/identity.key", home);
  return path;
}

static bool deriveEd25519PublicKey(const unsigned char seed[IDENTITY_KEY_BYTES],
                                   unsigned char pub[IDENTITY_KEY_BYTES]) {
  EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed,
                                                IDENTITY_KEY_BYTES);
  if (!pkey)
    return false;

  size_t pubLen = IDENTITY_KEY_BYTES;
  int ok = EVP_PKEY_get_raw_public_key(pkey, pub, &pubLen);
  EVP_PKEY_free(pkey);
  return ok == 1 && pubLen == IDENTITY_KEY_BYTES;
}

bool identityLoadOrCreate(Identity *id) {
  memset(id, 0, sizeof(*id));

  char *path = identityFilePath();
  if (!path)
    return false;

  FILE *f = fopen(path, "rb");
  if (f) {
    size_t n = fread(id->priv, 1, IDENTITY_KEY_BYTES, f);
    fclose(f);
    if (n == IDENTITY_KEY_BYTES) {
      if (!deriveEd25519PublicKey(id->priv, id->pub)) {
        fprintf(stderr, "identity: failed to derive public key\n");
        free(path);
        return false;
      }
      bytesToHex(id->pub, IDENTITY_KEY_BYTES, id->token);
      free(path);
      return true;
    }
    fprintf(stderr, "identity: key file truncated — regenerating\n");
  }

  if (RAND_bytes(id->priv, IDENTITY_KEY_BYTES) != 1) {
    fprintf(stderr, "identity: RAND_bytes failed\n");
    free(path);
    return false;
  }

  if (!deriveEd25519PublicKey(id->priv, id->pub)) {
    fprintf(stderr, "identity: failed to derive public key from new seed\n");
    free(path);
    return false;
  }

  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) {
    perror("identity: open identity.key for writing");
    free(path);
    return false;
  }
  ssize_t written = write(fd, id->priv, IDENTITY_KEY_BYTES);
  close(fd);
  if (written != (ssize_t)IDENTITY_KEY_BYTES) {
    fprintf(stderr, "identity: short write to identity.key\n");
    free(path);
    return false;
  }

  bytesToHex(id->pub, IDENTITY_KEY_BYTES, id->token);
  fprintf(stderr, "identity: new identity created — token: %s\n", id->token);
  free(path);
  return true;
}

bool identitySign(const Identity *id, const unsigned char *msg, size_t msgLen,
                  unsigned char sigOut[SIG_BYTES]) {
  EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                                id->priv, IDENTITY_KEY_BYTES);
  if (!pkey)
    return false;

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) {
    EVP_PKEY_free(pkey);
    return false;
  }

  bool ok = false;
  size_t sigLen = SIG_BYTES;

  if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey) == 1 &&
      EVP_DigestSign(ctx, sigOut, &sigLen, msg, msgLen) == 1 &&
      sigLen == SIG_BYTES) {
    ok = true;
  }

  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return ok;
}

bool identityVerify(const char *pubHex, const unsigned char *msg, size_t msgLen,
                    const unsigned char sig[SIG_BYTES]) {
  if (!pubHex || strlen(pubHex) != TOKEN_HEX_LEN)
    return false;

  unsigned char pubBytes[IDENTITY_KEY_BYTES];
  if (!hexToBytes(pubHex, TOKEN_HEX_LEN, pubBytes, IDENTITY_KEY_BYTES))
    return false;

  EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pubBytes,
                                               IDENTITY_KEY_BYTES);
  if (!pkey)
    return false;

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) {
    EVP_PKEY_free(pkey);
    return false;
  }

  void *sigVoid = (void *)sig;
  int rc = EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey);
  if (rc == 1)
    rc = EVP_DigestVerify(ctx, (const unsigned char *)sigVoid, SIG_BYTES, msg,
                          msgLen);

  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return rc == 1;
}

bool identityEd25519PubToX25519(
    const unsigned char ed25519Pub[IDENTITY_KEY_BYTES],
    unsigned char x25519Out[IDENTITY_KEY_BYTES]) {

  unsigned char y[32];
  memcpy(y, ed25519Pub, 32);
  y[31] &= 0x7f;

  BIGNUM *Y = BN_lebin2bn(y, 32, NULL);
  BIGNUM *one = BN_new();
  BIGNUM *p = BN_new();
  BIGNUM *num = BN_new();
  BIGNUM *den = BN_new();
  BIGNUM *u = BN_new();
  BN_CTX *bnctx = BN_CTX_new();

  bool ok = false;

  if (!Y || !one || !p || !num || !den || !u || !bnctx)
    goto bnout;

  BN_one(one);

  BN_set_bit(p, 255);
  BN_sub_word(p, 19);

  BN_mod_add(num, one, Y, p, bnctx);

  BN_mod_sub(den, one, Y, p, bnctx);

  BN_mod_inverse(den, den, p, bnctx);
  BN_mod_mul(u, num, den, p, bnctx);

  if (BN_bn2lebinpad(u, x25519Out, 32) == 32)
    ok = true;

bnout:
  BN_free(Y);
  BN_free(one);
  BN_free(p);
  BN_free(num);
  BN_free(den);
  BN_free(u);
  BN_CTX_free(bnctx);
  return ok;
}

bool identityEd25519PrivToX25519(
    const unsigned char ed25519Priv[IDENTITY_KEY_BYTES],
    unsigned char x25519Out[IDENTITY_KEY_BYTES]) {

  unsigned char h[64];
  if (SHA512(ed25519Priv, IDENTITY_KEY_BYTES, h) == NULL)
    return false;

  memcpy(x25519Out, h, 32);
  x25519Out[0] &= 248;
  x25519Out[31] &= 127;
  x25519Out[31] |= 64;

  memset(h, 0, sizeof(h));
  return true;
}

void identityPrintToken(const Identity *id) {
  printf("Your token: %s\n", id->token);
}
