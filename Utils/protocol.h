#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "socketUtil.h"

#define PROTOCOL_MAX_PARTS 16

size_t protocolSplitFields(char *line, char **parts, size_t maxParts);
bool protocolIsSafeIdentifier(const char *value);
bool protocolEncodeText(const char *text, char *encoded, size_t encodedSize);
bool protocolDecodeText(const char *encoded, char *text, size_t textSize);
