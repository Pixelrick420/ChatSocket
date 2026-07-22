#include "protocol.h"

#include "aes.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>

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

bool protocolParsePort(const char *value, int *out) {
  if (!value || !value[0] || !out)
    return false;
  for (size_t i = 0; value[i]; i++) {
    if (!isdigit((unsigned char)value[i]))
      return false;
  }
  errno = 0;
  char *end = NULL;
  long parsed = strtol(value, &end, 10);
  if (errno != 0 || !end || *end != '\0' || parsed < 1 || parsed > 65535)
    return false;
  *out = (int)parsed;
  return true;
}

ProtocolRoomCreateMode protocolParseRoomCreateArgs(
    const char *args, char *room, size_t roomSize, const char **secretOut) {
  if (!args || !room || roomSize < 2 || !secretOut)
    return PROTOCOL_ROOM_CREATE_INVALID;
  *secretOut = NULL;

  while (isspace((unsigned char)*args))
    args++;
  const char *roomStart = args;
  while (*args && !isspace((unsigned char)*args))
    args++;
  size_t roomLen = (size_t)(args - roomStart);
  if (roomLen == 0 || roomLen >= roomSize)
    return PROTOCOL_ROOM_CREATE_INVALID;
  memcpy(room, roomStart, roomLen);
  room[roomLen] = '\0';
  if (!protocolIsSafeIdentifier(room))
    return PROTOCOL_ROOM_CREATE_INVALID;

  while (isspace((unsigned char)*args))
    args++;
  if (!*args)
    return PROTOCOL_ROOM_CREATE_OPEN;
  if (args[0] != '-' || args[1] != 'p' ||
      (args[2] && !isspace((unsigned char)args[2])))
    return PROTOCOL_ROOM_CREATE_INVALID;

  args += 2;
  while (isspace((unsigned char)*args))
    args++;
  if (!*args)
    return PROTOCOL_ROOM_CREATE_PROMPT;
  *secretOut = args;
  return PROTOCOL_ROOM_CREATE_INLINE;
}

bool protocolBuildAuthTranscript(const unsigned char *nonce, size_t nonceLen,
                                 const char *certificateFingerprint,
                                 unsigned char *out, size_t outSize,
                                 size_t *outLen) {
  static const unsigned char prefix[] = "socketchat-auth-v4|";
  size_t prefixLen = sizeof(prefix) - 1;
  size_t fingerprintLen =
      certificateFingerprint ? strlen(certificateFingerprint) : 0;
  if (!nonce || !certificateFingerprint || fingerprintLen != 64 || !out ||
      !outLen || prefixLen >= outSize || nonceLen >= outSize - prefixLen ||
      fingerprintLen > outSize - prefixLen - nonceLen - 1)
    return false;

  if (!protocolIsHex(certificateFingerprint, fingerprintLen))
    return false;

  memcpy(out, prefix, prefixLen);
  memcpy(out + prefixLen, nonce, nonceLen);
  out[prefixLen + nonceLen] = '|';
  memcpy(out + prefixLen + nonceLen + 1, certificateFingerprint,
         fingerprintLen);
  *outLen = prefixLen + nonceLen + 1 + fingerprintLen;
  return true;
}

bool protocolBuildRoomAad(const char *roomName, const char *senderName,
                          const char *senderToken, const char *sessionId,
                          uint64_t sequence, char *out, size_t outSize,
                          size_t *outLen) {
  if (!roomName || !senderName || !senderToken || !sessionId || !out ||
      !outLen || sequence == 0)
    return false;
  int written = snprintf(out, outSize, "socketchat-room-v4|%s|%s|%s|%s|%" PRIu64,
                         roomName, senderName, senderToken, sessionId, sequence);
  if (written <= 0 || (size_t)written >= outSize)
    return false;
  *outLen = (size_t)written;
  return true;
}

bool protocolBuildRoomTranscript(const char *roomName, const char *senderName,
                                 const char *senderToken,
                                 const char *sessionId, uint64_t sequence,
                                 const char *payload, char *out,
                                 size_t outSize, size_t *outLen) {
  size_t aadLen = 0;
  if (!payload || !protocolBuildRoomAad(roomName, senderName, senderToken,
                                        sessionId, sequence, out, outSize,
                                        &aadLen) ||
      aadLen + 1 >= outSize)
    return false;
  int written = snprintf(out + aadLen, outSize - aadLen, "|%s", payload);
  if (written <= 0 || (size_t)written >= outSize - aadLen)
    return false;
  *outLen = aadLen + (size_t)written;
  return true;
}

bool protocolAcceptRoomSequence(RoomReplayTracker *tracker,
                                const char *senderToken,
                                const char *sessionId, uint64_t sequence) {
  if (!tracker || !protocolIsHex(senderToken, 64) ||
      !protocolIsHex(sessionId, 32) || sequence == 0)
    return false;

  RoomReplayPeer *peer = NULL;
  for (size_t i = 0; i < ROOM_REPLAY_PEERS; i++) {
    if (strcmp(tracker->peers[i].token, senderToken) == 0) {
      peer = &tracker->peers[i];
      break;
    }
    if (!peer && !tracker->peers[i].token[0])
      peer = &tracker->peers[i];
  }
  if (!peer)
    return false;

  if (strcmp(peer->token, senderToken) == 0 &&
      strcmp(peer->sessionId, sessionId) == 0) {
    if (peer->sequence == UINT64_MAX || sequence != peer->sequence + 1)
      return false;
    peer->sequence = sequence;
    return true;
  }

  if (sequence != 1)
    return false;
  for (size_t i = 0; i < ROOM_REPLAY_SESSIONS; i++) {
    if (strcmp(tracker->seenSessions[i], sessionId) == 0)
      return false;
  }

  snprintf(peer->token, sizeof(peer->token), "%s", senderToken);
  snprintf(peer->sessionId, sizeof(peer->sessionId), "%s", sessionId);
  peer->sequence = sequence;
  snprintf(tracker->seenSessions[tracker->seenNext],
           sizeof(tracker->seenSessions[tracker->seenNext]), "%s", sessionId);
  tracker->seenNext = (tracker->seenNext + 1) % ROOM_REPLAY_SESSIONS;
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
