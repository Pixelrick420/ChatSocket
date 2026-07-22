#include "aes.h"

#include <limits.h>
#include <openssl/kdf.h>

#define GCM_NONCE_LEN 12
#define GCM_TAG_LEN 16
#define GCM_OVERHEAD (GCM_NONCE_LEN + GCM_TAG_LEN)

int encryptMessage(const unsigned char *plaintext, size_t plaintext_len,
                   const unsigned char *key, unsigned char *ciphertext,
                   size_t ciphertextSize) {
  return encryptMessageWithAad(plaintext, plaintext_len, key, NULL, 0,
                               ciphertext, ciphertextSize);
}

int encryptMessageWithAad(const unsigned char *plaintext, size_t plaintext_len,
                          const unsigned char *key, const unsigned char *aad,
                          size_t aadLen, unsigned char *ciphertext,
                          size_t ciphertextSize) {

  if (!plaintext || !key || !ciphertext || plaintext_len > INT_MAX ||
      aadLen > INT_MAX || (aadLen > 0 && !aad) ||
      plaintext_len > ciphertextSize ||
      ciphertextSize - plaintext_len < GCM_OVERHEAD)
    return -1;

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
  if (aadLen > 0 &&
      EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aadLen) != 1)
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
                   const unsigned char *key, unsigned char *plaintext,
                   size_t plaintextSize) {
  return decryptMessageWithAad(ciphertext, ciphertext_len, key, NULL, 0,
                               plaintext, plaintextSize);
}

int decryptMessageWithAad(const unsigned char *ciphertext,
                          size_t ciphertext_len, const unsigned char *key,
                          const unsigned char *aad, size_t aadLen,
                          unsigned char *plaintext, size_t plaintextSize) {

  if (!ciphertext || !key || !plaintext || ciphertext_len < GCM_OVERHEAD ||
      aadLen > INT_MAX || (aadLen > 0 && !aad))
    return -1;

  const unsigned char *nonce = ciphertext;
  const unsigned char *tag = ciphertext + GCM_NONCE_LEN;
  const unsigned char *body = ciphertext + GCM_OVERHEAD;
  size_t bodyLen = ciphertext_len - GCM_OVERHEAD;
  if (bodyLen > plaintextSize || bodyLen > INT_MAX)
    return -1;

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
  if (aadLen > 0 &&
      EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aadLen) != 1)
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

bool encodeBase64(const unsigned char *input, size_t length, char *output,
                  size_t outputSize) {
  if (!input || !output || length > INT_MAX || length > SIZE_MAX - 2)
    return false;

  size_t required = ((length + 2) / 3) * 4 + 1;
  if (required > outputSize)
    return false;

  int written = EVP_EncodeBlock((unsigned char *)output, input, (int)length);
  if (written < 0 || (size_t)written + 1 > outputSize)
    return false;
  output[written] = '\0';
  return true;
}

int decodeBase64(const char *input, unsigned char *output, size_t outputSize) {
  if (!input || !output)
    return -1;

  size_t inputLen = strlen(input);
  if (inputLen == 0 || inputLen > INT_MAX || inputLen % 4 != 0)
    return -1;

  size_t decodedMax = (inputLen / 4) * 3;
  if (decodedMax > outputSize)
    return -1;

  int decoded = EVP_DecodeBlock(output, (const unsigned char *)input,
                                (int)inputLen);
  if (decoded < 0)
    return -1;

  if (inputLen >= 1 && input[inputLen - 1] == '=')
    decoded--;
  if (inputLen >= 2 && input[inputLen - 2] == '=')
    decoded--;
  return decoded;
}

void bytesToHex(const unsigned char *input, size_t length, char *output) {
  static const char hex[] = "0123456789abcdef";
  for (size_t i = 0; i < length; i++) {
    output[i * 2] = hex[input[i] >> 4];
    output[i * 2 + 1] = hex[input[i] & 0x0f];
  }
  output[length * 2] = '\0';
}

bool hexToBytes(const char *input, unsigned char *output, size_t outputLen) {
  if (!input || strlen(input) != outputLen * 2)
    return false;

  for (size_t i = 0; i < outputLen; i++) {
    unsigned char hi;
    unsigned char lo;
    char hc = input[i * 2];
    char lc = input[i * 2 + 1];

    if (hc >= '0' && hc <= '9')
      hi = (unsigned char)(hc - '0');
    else if (hc >= 'a' && hc <= 'f')
      hi = (unsigned char)(hc - 'a' + 10);
    else if (hc >= 'A' && hc <= 'F')
      hi = (unsigned char)(hc - 'A' + 10);
    else
      return false;

    if (lc >= '0' && lc <= '9')
      lo = (unsigned char)(lc - '0');
    else if (lc >= 'a' && lc <= 'f')
      lo = (unsigned char)(lc - 'a' + 10);
    else if (lc >= 'A' && lc <= 'F')
      lo = (unsigned char)(lc - 'A' + 10);
    else
      return false;

    output[i] = (unsigned char)((hi << 4) | lo);
  }

  return true;
}

static bool deriveRoomMaterial(const char *password, const unsigned char *salt,
                               size_t saltLen, const char *label,
                               unsigned char output[32]) {
  unsigned char derivedSalt[128];
  int written = snprintf((char *)derivedSalt, sizeof(derivedSalt), "%s:", label);
  if (written <= 0 || (size_t)written + saltLen > sizeof(derivedSalt))
    return false;
  memcpy(derivedSalt + written, salt, saltLen);

  if (EVP_PBE_scrypt(password, strlen(password), derivedSalt,
                     (size_t)written + saltLen, 32768, 8, 1,
                     64U * 1024U * 1024U, output, 32) != 1) {
    return false;
  }
  return true;
}

bool createRoomSecrets(const char *roomName, const char *password,
                       char saltHex[ROOM_SALT_HEX_SIZE],
                       char verifierHex[SHA256_HEX_SIZE],
                       unsigned char keyOut[32]) {
  unsigned char salt[ROOM_SALT_LEN];
  if (!roomName || !password || strlen(password) < ROOM_SECRET_MIN_LEN ||
      !saltHex || !verifierHex || !keyOut)
    return false;
  if (RAND_bytes(salt, sizeof(salt)) != 1)
    return false;

  bytesToHex(salt, sizeof(salt), saltHex);

  bool ok = false;
  unsigned char verifierBytes[32] = {0};
  unsigned char roomMix[32] = {0};
  if (!deriveRoomMaterial(password, salt, sizeof(salt), "socketchat-room-proof",
                          keyOut))
    goto out;

  if (!deriveRoomMaterial(password, salt, sizeof(salt),
                          "socketchat-room-verifier", verifierBytes))
    goto out;
  bytesToHex(verifierBytes, sizeof(verifierBytes), verifierHex);

  if (roomName[0]) {
    sha256Bytes(roomName, strlen(roomName), roomMix);
    for (int i = 0; i < 32; i++)
      keyOut[i] ^= roomMix[i];
  }
  ok = true;

out:
  OPENSSL_cleanse(salt, sizeof(salt));
  OPENSSL_cleanse(verifierBytes, sizeof(verifierBytes));
  OPENSSL_cleanse(roomMix, sizeof(roomMix));
  if (!ok) {
    OPENSSL_cleanse(keyOut, 32);
    verifierHex[0] = '\0';
  }
  return ok;
}

bool verifyRoomSecret(const char *roomName, const char *password,
                      const char *saltHex,
                      char verifierHex[SHA256_HEX_SIZE],
                      unsigned char keyOut[32]) {
  unsigned char salt[ROOM_SALT_LEN];
  if (!roomName || !password || !saltHex || !verifierHex || !keyOut)
    return false;
  if (!hexToBytes(saltHex, salt, sizeof(salt)))
    return false;

  bool ok = false;
  unsigned char verifierBytes[32] = {0};
  unsigned char roomMix[32] = {0};
  if (!deriveRoomMaterial(password, salt, sizeof(salt), "socketchat-room-proof",
                          keyOut))
    goto out;

  if (!deriveRoomMaterial(password, salt, sizeof(salt),
                          "socketchat-room-verifier", verifierBytes))
    goto out;
  bytesToHex(verifierBytes, sizeof(verifierBytes), verifierHex);

  if (roomName[0]) {
    sha256Bytes(roomName, strlen(roomName), roomMix);
    for (int i = 0; i < 32; i++)
      keyOut[i] ^= roomMix[i];
  }
  ok = true;

out:
  OPENSSL_cleanse(salt, sizeof(salt));
  OPENSSL_cleanse(verifierBytes, sizeof(verifierBytes));
  OPENSSL_cleanse(roomMix, sizeof(roomMix));
  if (!ok) {
    OPENSSL_cleanse(keyOut, 32);
    verifierHex[0] = '\0';
  }
  return ok;
}
