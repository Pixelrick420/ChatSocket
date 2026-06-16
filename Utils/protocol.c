#include "protocol.h"

#include "aes.h"

#include <ctype.h>

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

bool protocolEncodeText(const char *text, char *encoded, size_t encodedSize) {
  if (!text || !encoded || encodedSize == 0)
    return false;

  size_t textLen = strlen(text);
  size_t required = ((textLen + 2) / 3) * 4 + 1;
  if (required > encodedSize)
    return false;

  encodeBase64((const unsigned char *)text, textLen, encoded);
  return true;
}

bool protocolDecodeText(const char *encoded, char *text, size_t textSize) {
  if (!encoded || !text || textSize == 0)
    return false;

  unsigned char decoded[MSG_SIZE];
  int decodedLen = decodeBase64(encoded, decoded);
  if (decodedLen < 0 || (size_t)decodedLen >= textSize)
    return false;

  memcpy(text, decoded, (size_t)decodedLen);
  text[decodedLen] = '\0';
  return true;
}
