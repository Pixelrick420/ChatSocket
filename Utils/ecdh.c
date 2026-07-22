#include "ecdh.h"

static bool ecdhDeriveSharedSecret(const unsigned char myPrivX25519[32],
                                   const unsigned char peerPubX25519[32],
                                   unsigned char sharedSecret[32]) {
  bool ok = false;
  EVP_PKEY *privKey = NULL;
  EVP_PKEY *pubKey = NULL;
  EVP_PKEY_CTX *ctx = NULL;

  size_t sharedLen = 32;

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

  ok = true;

out:
  if (ctx)
    EVP_PKEY_CTX_free(ctx);
  if (privKey)
    EVP_PKEY_free(privKey);
  if (pubKey)
    EVP_PKEY_free(pubKey);
  if (!ok)
    OPENSSL_cleanse(sharedSecret, 32);
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
                          const char *sessionId,
                          const unsigned char initiatorPub[32],
                          const unsigned char responderPub[32],
                          unsigned char keyOut[32]) {
  unsigned char shared[32];
  if (!initiatorToken || !responderToken || !sessionId || !initiatorPub ||
      !responderPub)
    return false;
  if (!ecdhDeriveSharedSecret(myPrivX25519, peerPubX25519, shared))
    return false;

  bool ok = false;
  EVP_KDF_CTX *kctx = NULL;
  EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
  if (!kdf)
    goto out;
  kctx = EVP_KDF_CTX_new(kdf);
  EVP_KDF_free(kdf);
  if (!kctx)
    goto out;

  unsigned char infoBuf[256];
  int infoLen = snprintf((char *)infoBuf, sizeof(infoBuf),
                         "socketchat-dm-v4|%s|%s|%s|", initiatorToken,
                         responderToken, sessionId);
  if (infoLen <= 0 || (size_t)infoLen + 64 > sizeof(infoBuf))
    goto out;
  memcpy(infoBuf + infoLen, initiatorPub, 32);
  memcpy(infoBuf + infoLen + 32, responderPub, 32);
  infoLen += 64;

  static const unsigned char salt[] = "socketchat-dm-v4";
  char digestName[] = "SHA256";
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_utf8_string("digest", digestName, 0),
      OSSL_PARAM_construct_octet_string("key", shared, sizeof(shared)),
      OSSL_PARAM_construct_octet_string("salt", (void *)salt, sizeof(salt) - 1),
      OSSL_PARAM_construct_octet_string("info", infoBuf, (size_t)infoLen),
      OSSL_PARAM_construct_end()};

  ok = EVP_KDF_derive(kctx, keyOut, 32, params) > 0;

out:
  if (kctx)
    EVP_KDF_CTX_free(kctx);
  OPENSSL_cleanse(shared, sizeof(shared));
  return ok;
}
