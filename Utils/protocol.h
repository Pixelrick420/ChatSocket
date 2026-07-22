#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "socketUtil.h"

#define PROTOCOL_MAX_PARTS 16
#define PROTOCOL_MAX_PAYLOAD 1920
#define PROTOCOL_VERSION "4"
#define ROOM_REPLAY_PEERS 32
#define ROOM_REPLAY_SESSIONS 256

typedef struct {
  char token[65];
  char sessionId[33];
  uint64_t sequence;
} RoomReplayPeer;

typedef struct {
  RoomReplayPeer peers[ROOM_REPLAY_PEERS];
  char seenSessions[ROOM_REPLAY_SESSIONS][33];
  size_t seenNext;
} RoomReplayTracker;

size_t protocolSplitFields(char *line, char **parts, size_t maxParts);
bool protocolIsSafeIdentifier(const char *value);
bool protocolIsHex(const char *value, size_t expectedLen);
bool protocolIsSafeText(const char *value, size_t maxLen);
bool protocolParseSequence(const char *value, uint64_t *out);
bool protocolParsePort(const char *value, int *out);
bool protocolBuildAuthTranscript(const unsigned char *nonce, size_t nonceLen,
                                 const char *certificateFingerprint,
                                 unsigned char *out, size_t outSize,
                                 size_t *outLen);
bool protocolBuildRoomAad(const char *roomName, const char *senderName,
                          const char *senderToken, const char *sessionId,
                          uint64_t sequence, char *out, size_t outSize,
                          size_t *outLen);
bool protocolBuildRoomTranscript(const char *roomName, const char *senderName,
                                 const char *senderToken,
                                 const char *sessionId, uint64_t sequence,
                                 const char *payload, char *out,
                                 size_t outSize, size_t *outLen);
bool protocolAcceptRoomSequence(RoomReplayTracker *tracker,
                                const char *senderToken,
                                const char *sessionId, uint64_t sequence);
bool protocolEncodeText(const char *text, char *encoded, size_t encodedSize);
bool protocolDecodeText(const char *encoded, char *text, size_t textSize);
