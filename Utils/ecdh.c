#include "ecdh.h"

static int hexNibble(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

bool ecdhDeriveKey(const unsigned char myPrivX25519[32],
                   const unsigned char peerPubX25519[32],
                   unsigned char keyOut[32]) {
  bool ok = false;
  EVP_PKEY *privKey = NULL;
  EVP_PKEY *pubKey = NULL;
  EVP_PKEY_CTX *ctx = NULL;

  unsigned char sharedSecret[32];
  size_t sharedLen = sizeof(sharedSecret);

  privKey =
      EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, myPrivX25519, 32);
  if (!privKey) {
    fprintf(stderr, "ecdh: bad X25519 private key\n");
    goto out;
  }

  pubKey =
      EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peerPubX25519, 32);
  if (!pubKey) {
    fprintf(stderr, "ecdh: bad X25519 public key\n");
    goto out;
  }

  ctx = EVP_PKEY_CTX_new(privKey, NULL);
  if (!ctx)
    goto out;
  if (EVP_PKEY_derive_init(ctx) <= 0)
    goto out;
  if (EVP_PKEY_derive_set_peer(ctx, pubKey) <= 0)
    goto out;
  if (EVP_PKEY_derive(ctx, sharedSecret, &sharedLen) <= 0)
    goto out;

  {
    unsigned char z = 0;
    for (int i = 0; i < 32; i++)
      z |= sharedSecret[i];
    if (z == 0) {
      fprintf(stderr, "ecdh: low-order point\n");
      goto out;
    }
  }

  {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf)
      goto out;
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx)
      goto out;

    static const char saltStr[] = "socketchat-dm-v1";
    unsigned char saltBuf[sizeof(saltStr) - 1];
    memcpy(saltBuf, saltStr, sizeof(saltBuf));

    unsigned char keyBuf[32];
    memcpy(keyBuf, sharedSecret, 32);

    char digestName[] = "SHA256";

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", digestName, 0),
        OSSL_PARAM_construct_octet_string("key", keyBuf, 32),
        OSSL_PARAM_construct_octet_string("salt", saltBuf, sizeof(saltBuf)),
        OSSL_PARAM_construct_end()};

    int rc = EVP_KDF_derive(kctx, keyOut, 32, params);
    EVP_KDF_CTX_free(kctx);
    memset(keyBuf, 0, sizeof(keyBuf));
    if (rc <= 0) {
      fprintf(stderr, "ecdh: HKDF failed\n");
      goto out;
    }
  }

  ok = true;

out:
  if (ctx)
    EVP_PKEY_CTX_free(ctx);
  if (privKey)
    EVP_PKEY_free(privKey);
  if (pubKey)
    EVP_PKEY_free(pubKey);
  memset(sharedSecret, 0, sizeof(sharedSecret));
  return ok;
}

bool x25519GenerateKeypair(unsigned char pubOut[32], unsigned char privOut[32]) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
  EVP_PKEY *key = NULL;
  bool ok = false;

  if (!ctx)
    return false;
  if (EVP_PKEY_keygen_init(ctx) <= 0)
    goto out;
  if (EVP_PKEY_keygen(ctx, &key) <= 0)
    goto out;

  size_t privLen = 32;
  size_t pubLen = 32;
  if (EVP_PKEY_get_raw_private_key(key, privOut, &privLen) != 1 || privLen != 32)
    goto out;
  if (EVP_PKEY_get_raw_public_key(key, pubOut, &pubLen) != 1 || pubLen != 32)
    goto out;

  ok = true;

out:
  if (key)
    EVP_PKEY_free(key);
  EVP_PKEY_CTX_free(ctx);
  return ok;
}

bool ecdhDeriveSessionKey(const unsigned char myPrivX25519[32],
                          const unsigned char peerPubX25519[32],
                          const char *initiatorToken,
                          const char *responderToken,
                          const unsigned char initiatorPub[32],
                          const unsigned char responderPub[32],
                          unsigned char keyOut[32]) {
  unsigned char shared[32];
  if (!initiatorToken || !responderToken || !initiatorPub || !responderPub)
    return false;
  if (!ecdhDeriveKey(myPrivX25519, peerPubX25519, shared))
    return false;

  bool ok = false;
  EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
  if (!kdf)
    return false;
  EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
  EVP_KDF_free(kdf);
  if (!kctx)
    return false;

  unsigned char infoBuf[256];
  int infoLen = snprintf((char *)infoBuf, sizeof(infoBuf), "socketchat-dm-v2|%s|%s|",
                         initiatorToken, responderToken);
  if (infoLen <= 0 || (size_t)infoLen + 64 > sizeof(infoBuf))
    goto out;
  memcpy(infoBuf + infoLen, initiatorPub, 32);
  memcpy(infoBuf + infoLen + 32, responderPub, 32);
  infoLen += 64;

  static const unsigned char salt[] = "socketchat-dm-v2";
  char digestName[] = "SHA256";
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_utf8_string("digest", digestName, 0),
      OSSL_PARAM_construct_octet_string("key", shared, sizeof(shared)),
      OSSL_PARAM_construct_octet_string("salt", (void *)salt, sizeof(salt) - 1),
      OSSL_PARAM_construct_octet_string("info", infoBuf, (size_t)infoLen),
      OSSL_PARAM_construct_end()};

  ok = EVP_KDF_derive(kctx, keyOut, 32, params) > 0;

out:
  EVP_KDF_CTX_free(kctx);
  memset(shared, 0, sizeof(shared));
  return ok;
}

bool tokenToX25519PublicKey(const char *token, unsigned char x25519Out[32]) {
  if (!token || strlen(token) != TOKEN_HEX_LEN)
    return false;

  unsigned char ed25519Pub[IDENTITY_KEY_BYTES];
  for (int i = 0; i < 32; i++) {
    int hi = hexNibble(token[i * 2]);
    int lo = hexNibble(token[i * 2 + 1]);
    if (hi < 0 || lo < 0)
      return false;
    ed25519Pub[i] = (unsigned char)((hi << 4) | lo);
  }

  return identityEd25519PubToX25519(ed25519Pub, x25519Out);
}
