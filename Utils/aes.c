#include "aes.h"

#define GCM_NONCE_LEN 12
#define GCM_TAG_LEN 16
#define GCM_OVERHEAD (GCM_NONCE_LEN + GCM_TAG_LEN)

void deriveKeyFromPassword(const char *password, unsigned char *key) {
  sha256Bytes(password, strlen(password), key);
}

int encryptMessage(const unsigned char *plaintext, size_t plaintext_len,
                   const unsigned char *key, unsigned char *ciphertext) {

  unsigned char nonce[GCM_NONCE_LEN];
  if (RAND_bytes(nonce, GCM_NONCE_LEN) != 1)
    return -1;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    return -1;

  int len = 0, ciphertext_len = 0;

  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
    goto err;

  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_LEN, NULL) !=
      1)
    goto err;
  if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
    goto err;
  if (EVP_EncryptUpdate(ctx, ciphertext + GCM_OVERHEAD, &len, plaintext,
                        (int)plaintext_len) != 1)
    goto err;
  ciphertext_len = len;
  if (EVP_EncryptFinal_ex(ctx, ciphertext + GCM_OVERHEAD + len, &len) != 1)
    goto err;
  ciphertext_len += len;

  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN,
                          ciphertext + GCM_NONCE_LEN) != 1)
    goto err;

  memcpy(ciphertext, nonce, GCM_NONCE_LEN);

  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len + GCM_OVERHEAD;

err:
  EVP_CIPHER_CTX_free(ctx);
  return -1;
}

int decryptMessage(const unsigned char *ciphertext, size_t ciphertext_len,
                   const unsigned char *key, unsigned char *plaintext) {

  if (ciphertext_len < GCM_OVERHEAD)
    return -1;

  const unsigned char *nonce = ciphertext;
  const unsigned char *tag = ciphertext + GCM_NONCE_LEN;
  const unsigned char *body = ciphertext + GCM_OVERHEAD;
  size_t bodyLen = ciphertext_len - GCM_OVERHEAD;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    return -1;

  int len = 0, plaintext_len = 0;

  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
    goto err;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_LEN, NULL) !=
      1)
    goto err;
  if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
    goto err;
  if (EVP_DecryptUpdate(ctx, plaintext, &len, body, (int)bodyLen) != 1)
    goto err;
  plaintext_len = len;

  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN,
                          (void *)tag) != 1)
    goto err;

  if (EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &len) != 1)
    goto err;
  plaintext_len += len;

  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;

err:

  if (plaintext_len > 0)
    memset(plaintext, 0, (size_t)plaintext_len);
  EVP_CIPHER_CTX_free(ctx);
  return -1;
}

void encodeBase64(const unsigned char *input, size_t length, char *output) {
  EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
  int outlen = 0, final_len = 0;

  EVP_EncodeInit(ctx);
  EVP_EncodeUpdate(ctx, (unsigned char *)output, &outlen, input, (int)length);
  EVP_EncodeFinal(ctx, (unsigned char *)(output + outlen), &final_len);
  EVP_ENCODE_CTX_free(ctx);

  char *src = output;
  char *dst = output;
  while (*src) {
    if (*src != '\n' && *src != '\r')
      *dst++ = *src;
    src++;
  }
  *dst = '\0';
}

int decodeBase64(const char *input, unsigned char *output) {
  EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
  int outlen = 0, final_len = 0;

  EVP_DecodeInit(ctx);
  if (EVP_DecodeUpdate(ctx, output, &outlen, (const unsigned char *)input,
                       (int)strlen(input)) == -1) {
    EVP_ENCODE_CTX_free(ctx);
    return -1;
  }
  if (EVP_DecodeFinal(ctx, output + outlen, &final_len) == -1) {
    EVP_ENCODE_CTX_free(ctx);
    return -1;
  }

  EVP_ENCODE_CTX_free(ctx);
  return outlen + final_len;
}

bool isEncryptedMessage(const char *buffer) {
  return strncmp(buffer, "ENC:", 4) == 0;
}
