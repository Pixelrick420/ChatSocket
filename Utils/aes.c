#include "aes.h"

void deriveKeyFromPassword(const char *password, unsigned char *key)
{
    sha256Bytes(password, strlen(password), key);
}

int encryptMessage(const unsigned char *plaintext, size_t plaintext_len,
                   const unsigned char *key, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    unsigned char iv[16];

    if (RAND_bytes(iv, 16) != 1)
        return -1;

    memcpy(ciphertext, iv, 16);

    if (!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext + 16, &len, plaintext, plaintext_len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + 16 + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len + 16;
}

int decryptMessage(const unsigned char *ciphertext, size_t ciphertext_len,
                   const unsigned char *key, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    unsigned char iv[16];

    if (ciphertext_len < 16)
        return -1;

    memcpy(iv, ciphertext, 16);

    if (!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext + 16, ciphertext_len - 16) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    return plaintext_len;
}

void encodeBase64(const unsigned char *input, size_t length, char *output)
{
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    int outlen;
    EVP_EncodeInit(ctx);
    EVP_EncodeUpdate(ctx, (unsigned char *)output, &outlen, input, length);
    int final_len;
    EVP_EncodeFinal(ctx, (unsigned char *)(output + outlen), &final_len);
    output[outlen + final_len] = '\0';

    for (int i = 0; output[i]; i++)
    {
        if (output[i] == '\n' || output[i] == '\r')
            output[i] = '\0';
    }

    EVP_ENCODE_CTX_free(ctx);
}

int decodeBase64(const char *input, unsigned char *output)
{
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    int outlen;
    int final_len;

    EVP_DecodeInit(ctx);
    if (EVP_DecodeUpdate(ctx, output, &outlen, (const unsigned char *)input, strlen(input)) == -1)
    {
        EVP_ENCODE_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecodeFinal(ctx, output + outlen, &final_len) == -1)
    {
        EVP_ENCODE_CTX_free(ctx);
        return -1;
    }

    EVP_ENCODE_CTX_free(ctx);
    return outlen + final_len;
}

bool isEncryptedMessage(const char *buffer)
{
    return strncmp(buffer, "ENC:", 4) == 0;
}
