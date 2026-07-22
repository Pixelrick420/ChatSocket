#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "socketUtil.h"

#define PROTOCOL_MAX_PARTS 16
#define PROTOCOL_MAX_PAYLOAD 1920
#define PROTOCOL_VERSION "3"

size_t protocolSplitFields(char *line, char **parts, size_t maxParts);
bool protocolIsSafeIdentifier(const char *value);
bool protocolIsHex(const char *value, size_t expectedLen);
bool protocolIsSafeText(const char *value, size_t maxLen);
bool protocolParseSequence(const char *value, uint64_t *out);
bool protocolBuildAuthTranscript(const unsigned char *nonce, size_t nonceLen,
                                 unsigned char *out, size_t outSize,
                                 size_t *outLen);
bool protocolEncodeText(const char *text, char *encoded, size_t encodedSize);
bool protocolDecodeText(const char *encoded, char *text, size_t textSize);
