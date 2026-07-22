#include "../Utils/aes.h"
#include "../Utils/protocol.h"
#include "../Utils/socketUtil.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void testBase64Bounds(void) {
  const unsigned char input[] = "hello";
  char encoded[16];
  unsigned char decoded[16];

  assert(!encodeBase64(input, 5, encoded, 4));
  assert(encodeBase64(input, 5, encoded, sizeof(encoded)));
  assert(strcmp(encoded, "aGVsbG8=") == 0);
  assert(decodeBase64(encoded, decoded, 4) == -1);
  assert(decodeBase64(encoded, decoded, sizeof(decoded)) == 5);
  assert(memcmp(decoded, input, 5) == 0);
  assert(decodeBase64("not-base64", decoded, sizeof(decoded)) == -1);
}

static void testAesBoundsAndTamper(void) {
  const unsigned char plaintext[] = "authenticated message";
  unsigned char key[32] = {0};
  unsigned char ciphertext[sizeof(plaintext) - 1 + AES_GCM_OVERHEAD];
  unsigned char decrypted[sizeof(plaintext)] = {0};

  assert(encryptMessage(plaintext, sizeof(plaintext) - 1, key, ciphertext,
                        sizeof(ciphertext) - 1) == -1);
  int ciphertextLen =
      encryptMessage(plaintext, sizeof(plaintext) - 1, key, ciphertext,
                     sizeof(ciphertext));
  assert(ciphertextLen == (int)sizeof(ciphertext));
  assert(decryptMessage(ciphertext, (size_t)ciphertextLen, key, decrypted,
                        sizeof(plaintext) - 2) == -1);
  assert(decryptMessage(ciphertext, (size_t)ciphertextLen, key, decrypted,
                        sizeof(decrypted)) == (int)sizeof(plaintext) - 1);
  assert(memcmp(decrypted, plaintext, sizeof(plaintext) - 1) == 0);

  ciphertext[ciphertextLen - 1] ^= 1;
  assert(decryptMessage(ciphertext, (size_t)ciphertextLen, key, decrypted,
                        sizeof(decrypted)) == -1);
}

static void testAesAadBinding(void) {
  const unsigned char plaintext[] = "bound message";
  const unsigned char aad[] = "session|sender|1";
  const unsigned char wrongAad[] = "session|sender|2";
  unsigned char key[32] = {1};
  unsigned char ciphertext[sizeof(plaintext) - 1 + AES_GCM_OVERHEAD];
  unsigned char decrypted[sizeof(plaintext)] = {0};

  int ciphertextLen = encryptMessageWithAad(
      plaintext, sizeof(plaintext) - 1, key, aad, sizeof(aad) - 1, ciphertext,
      sizeof(ciphertext));
  assert(ciphertextLen == (int)sizeof(ciphertext));
  assert(decryptMessageWithAad(ciphertext, (size_t)ciphertextLen, key, aad,
                               sizeof(aad) - 1, decrypted,
                               sizeof(decrypted)) ==
         (int)sizeof(plaintext) - 1);
  assert(decryptMessageWithAad(ciphertext, (size_t)ciphertextLen, key, wrongAad,
                               sizeof(wrongAad) - 1, decrypted,
                               sizeof(decrypted)) == -1);
}

static void testRoomKdfDomainSeparation(void) {
  const char *salt = "000102030405060708090a0b0c0d0e0f";
  char verifierA[SHA256_HEX_SIZE];
  char verifierB[SHA256_HEX_SIZE];
  unsigned char verifierBytes[32];
  unsigned char keyA[32];
  unsigned char keyB[32];

  assert(!createRoomSecrets("room-a", "short", verifierA, verifierB, keyA));

  assert(verifyRoomSecret("room-a", "correct horse", salt, verifierA, keyA));
  assert(verifyRoomSecret("room-a", "correct horse", salt, verifierB, keyB));
  assert(strcmp(verifierA, verifierB) == 0);
  assert(memcmp(keyA, keyB, sizeof(keyA)) == 0);
  assert(hexToBytes(verifierA, verifierBytes, sizeof(verifierBytes)));
  assert(memcmp(keyA, verifierBytes, sizeof(keyA)) != 0);

  assert(verifyRoomSecret("room-b", "correct horse", salt, verifierB, keyB));
  assert(memcmp(keyA, keyB, sizeof(keyA)) != 0);
}

static void testProtocolValidation(void) {
  uint64_t sequence = 0;
  unsigned char nonce[32] = {0};
  const char *fingerprint =
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  unsigned char transcript[160];
  size_t transcriptLen = 0;
  assert(protocolIsHex("00aAfF", 6));
  assert(!protocolIsHex("00xz", 4));
  assert(protocolIsSafeText("hello world", MAX_MESSAGE_TEXT));
  assert(!protocolIsSafeText("hello\033[2J", MAX_MESSAGE_TEXT));
  assert(protocolParseSequence("1", &sequence) && sequence == 1);
  assert(protocolParseSequence("18446744073709551615", &sequence) &&
         sequence == UINT64_MAX);
  assert(!protocolParseSequence("0", &sequence));
  assert(!protocolParseSequence("01", &sequence));
  assert(!protocolParseSequence("18446744073709551616", &sequence));
  int port = 0;
  assert(protocolParsePort("2077", &port) && port == 2077);
  assert(!protocolParsePort("0", &port));
  assert(!protocolParsePort("65536", &port));
  assert(!protocolParsePort("20x", &port));
  assert(protocolBuildAuthTranscript(nonce, sizeof(nonce), fingerprint,
                                     transcript, sizeof(transcript),
                                     &transcriptLen));
  assert(transcriptLen == strlen("socketchat-auth-v4|") + sizeof(nonce) + 1 +
                              strlen(fingerprint));
  assert(memcmp(transcript, "socketchat-auth-v4|",
                strlen("socketchat-auth-v4|")) == 0);
  assert(!protocolBuildAuthTranscript(nonce, sizeof(nonce), "bad", transcript,
                                      sizeof(transcript), &transcriptLen));
}

static void testRoomCreateCommandParsing(void) {
  char room[64];
  const char *secret = NULL;

  assert(protocolParseRoomCreateArgs("lounge", room, sizeof(room), &secret) ==
         PROTOCOL_ROOM_CREATE_OPEN);
  assert(strcmp(room, "lounge") == 0 && secret == NULL);
  assert(protocolParseRoomCreateArgs("vault -p", room, sizeof(room), &secret) ==
         PROTOCOL_ROOM_CREATE_PROMPT);
  assert(secret == NULL);
  assert(protocolParseRoomCreateArgs("vault -p password1234", room,
                                     sizeof(room), &secret) ==
         PROTOCOL_ROOM_CREATE_INLINE);
  assert(strcmp(secret, "password1234") == 0);
  assert(protocolParseRoomCreateArgs("vault -p pass phrase 1234", room,
                                     sizeof(room), &secret) ==
         PROTOCOL_ROOM_CREATE_INLINE);
  assert(strcmp(secret, "pass phrase 1234") == 0);
  assert(protocolParseRoomCreateArgs("", room, sizeof(room), &secret) ==
         PROTOCOL_ROOM_CREATE_INVALID);
  assert(protocolParseRoomCreateArgs("bad!room -p password1234", room,
                                     sizeof(room), &secret) ==
         PROTOCOL_ROOM_CREATE_INVALID);
  assert(protocolParseRoomCreateArgs("vault --private password1234", room,
                                     sizeof(room), &secret) ==
         PROTOCOL_ROOM_CREATE_INVALID);
}

static void testRoomMessageBindingAndReplay(void) {
  const char *token =
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const char *sessionA = "00112233445566778899aabbccddeeff";
  const char *sessionB = "ffeeddccbbaa99887766554433221100";
  char aad[512];
  char transcript[1024];
  size_t aadLen = 0;
  size_t transcriptLen = 0;
  RoomReplayTracker tracker = {0};

  assert(protocolBuildRoomAad("vault", "Alice", token, sessionA, 1, aad,
                              sizeof(aad), &aadLen));
  assert(strstr(aad, "vault|Alice|") != NULL);
  assert(protocolBuildRoomTranscript("vault", "Alice", token, sessionA, 1,
                                     "payload", transcript,
                                     sizeof(transcript), &transcriptLen));
  assert(transcriptLen == aadLen + strlen("|payload"));
  assert(strncmp(transcript, aad, aadLen) == 0);

  assert(protocolAcceptRoomSequence(&tracker, token, sessionA, 1));
  assert(protocolAcceptRoomSequence(&tracker, token, sessionA, 2));
  assert(!protocolAcceptRoomSequence(&tracker, token, sessionA, 2));
  assert(!protocolAcceptRoomSequence(&tracker, token, sessionB, 2));
  assert(protocolAcceptRoomSequence(&tracker, token, sessionB, 1));
  assert(!protocolAcceptRoomSequence(&tracker, token, sessionA, 1));
}

static void testRoomCleanupKeepsClientIndexesValid(void) {
  ServerContext *context = createServerContext(INVALID_SOCKET_HANDLE, 2, 2);
  Room *expired = createRoom("expired", NULL);
  Room *active = createRoom("active", NULL);
  Client client = {0};

  assert(context && expired && active);
  expired->lastActivity = time(NULL) - ROOM_TIMEOUT - 1;
  assert(addMemberToRoom(active, 42));

  client.socketFD = 42;
  client.currentRoom = 1;
  context->clients[0] = &client;
  context->clientCount = 1;
  context->rooms[0] = expired;
  context->rooms[1] = active;
  context->roomCount = 2;

  cleanupInactiveRooms(context);
  assert(context->roomCount == 1);
  assert(context->rooms[0] == active);
  assert(client.currentRoom == 0);

  destroyServerContext(context);
}

static void testSecureUserFileValidation(void) {
#ifndef _WIN32
  char path[] = "/tmp/chatsocket-unit.XXXXXX";
  int fd = mkstemp(path);
  struct stat st;
  assert(fd >= 0);
  assert(fchmod(fd, 0644) == 0);
  assert(platformSecureUserFileFd(fd));
  assert(fstat(fd, &st) == 0 && (st.st_mode & 0777) == 0600);
  close(fd);
  unlink(path);

  int pipeFds[2];
  assert(pipe(pipeFds) == 0);
  assert(!platformSecureUserFileFd(pipeFds[0]));
  close(pipeFds[0]);
  close(pipeFds[1]);
#endif
}

int main(void) {
  testBase64Bounds();
  testAesBoundsAndTamper();
  testAesAadBinding();
  testRoomKdfDomainSeparation();
  testProtocolValidation();
  testRoomCreateCommandParsing();
  testRoomMessageBindingAndReplay();
  testRoomCleanupKeepsClientIndexesValid();
  testSecureUserFileValidation();
  puts("unit security tests passed");
  return 0;
}
