#include "protocol.h"

#include "aes.h"

#include <ctype.h>
#include <errno.h>

size_t protocolSplitFields(char *line, char **parts, size_t maxParts) {
  if (!line || !parts || maxParts == 0)
    return 0;

  size_t count = 0;
  parts[count++] = line;
  for (char *p = line; *p && count < maxParts; p++) {
    if (*p == '\r' || *p == '\n') {
      *p = '\0';
      break;
    }
    if (*p == '|') {
      *p = '\0';
      parts[count++] = p + 1;
    }
  }
  return count;
}

bool protocolIsSafeIdentifier(const char *value) {
  if (!value || !value[0] || strlen(value) >= MAX_NAME_LEN)
    return false;

  for (size_t i = 0; value[i]; i++) {
    unsigned char ch = (unsigned char)value[i];
    if (!(isalnum(ch) || ch == '-' || ch == '_' || ch == '.'))
      return false;
  }
  return true;
}

bool protocolIsHex(const char *value, size_t expectedLen) {
  if (!value || strlen(value) != expectedLen)
    return false;

  for (size_t i = 0; i < expectedLen; i++) {
    if (!isxdigit((unsigned char)value[i]))
      return false;
  }
  return true;
}

bool protocolIsSafeText(const char *value, size_t maxLen) {
  if (!value || strlen(value) > maxLen)
    return false;

  for (size_t i = 0; value[i]; i++) {
    unsigned char ch = (unsigned char)value[i];
    if (ch < 0x20 || ch == 0x7f)
      return false;
  }
  return true;
}

bool protocolParseSequence(const char *value, uint64_t *out) {
  if (!value || !value[0] || !out || strlen(value) > 20 || value[0] == '0')
    return false;

  for (size_t i = 0; value[i]; i++) {
    if (!isdigit((unsigned char)value[i]))
      return false;
  }

  errno = 0;
  char *end = NULL;
  unsigned long long parsed = strtoull(value, &end, 10);
  if (errno != 0 || !end || *end != '\0' || parsed == 0)
    return false;
  *out = (uint64_t)parsed;
  return true;
}

bool protocolBuildAuthTranscript(const unsigned char *nonce, size_t nonceLen,
                                 unsigned char *out, size_t outSize,
                                 size_t *outLen) {
  static const unsigned char prefix[] = "socketchat-auth-v3|";
  size_t prefixLen = sizeof(prefix) - 1;
  if (!nonce || !out || !outLen || nonceLen > outSize ||
      prefixLen > outSize - nonceLen)
    return false;

  memcpy(out, prefix, prefixLen);
  memcpy(out + prefixLen, nonce, nonceLen);
  *outLen = prefixLen + nonceLen;
  return true;
}

bool protocolEncodeText(const char *text, char *encoded, size_t encodedSize) {
  if (!text || !encoded || encodedSize == 0)
    return false;

  size_t textLen = strlen(text);
  size_t required = ((textLen + 2) / 3) * 4 + 1;
  if (required > encodedSize)
    return false;

  return encodeBase64((const unsigned char *)text, textLen, encoded,
                      encodedSize);
}

bool protocolDecodeText(const char *encoded, char *text, size_t textSize) {
  if (!encoded || !text || textSize == 0)
    return false;

  unsigned char decoded[MSG_SIZE];
  int decodedLen = decodeBase64(encoded, decoded, sizeof(decoded));
  if (decodedLen < 0 || (size_t)decodedLen >= textSize)
    return false;

  memcpy(text, decoded, (size_t)decodedLen);
  text[decodedLen] = '\0';
  return true;
}
