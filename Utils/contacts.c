#include "contacts.h"

#include <ctype.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <time.h>

enum {
  CONTACT_SCORE_NICK_EXACT = 1200,
  CONTACT_SCORE_TOKEN_EXACT = 1100,
  CONTACT_SCORE_NICK_PREFIX = 1000,
  CONTACT_SCORE_NICK_WORD = 950,
  CONTACT_SCORE_TOKEN_PREFIX = 800,
  CONTACT_SCORE_NICK_SUBSTRING = 700,
  CONTACT_SCORE_TOKEN_SUBSTRING = 550
};

typedef struct {
  size_t index;
  int score;
  time_t lastActive;
} RankedContactMatch;

static unsigned char asciiLower(unsigned char ch) {
  return (unsigned char)tolower(ch);
}

static bool equalsIgnoreCase(const char *lhs, const char *rhs) {
  if (!lhs || !rhs)
    return false;

  while (*lhs && *rhs) {
    if (asciiLower((unsigned char)*lhs) != asciiLower((unsigned char)*rhs))
      return false;
    lhs++;
    rhs++;
  }
  return *lhs == '\0' && *rhs == '\0';
}

static bool startsWithIgnoreCase(const char *text, const char *prefix) {
  if (!text || !prefix)
    return false;

  while (*prefix) {
    if (*text == '\0' ||
        asciiLower((unsigned char)*text) != asciiLower((unsigned char)*prefix))
      return false;
    text++;
    prefix++;
  }
  return true;
}

static bool containsIgnoreCase(const char *text, const char *query) {
  if (!text || !query || !query[0])
    return false;

  size_t queryLen = strlen(query);
  for (size_t i = 0; text[i]; i++) {
    if (startsWithIgnoreCase(&text[i], query))
      return true;
    if (strlen(&text[i]) < queryLen)
      break;
  }
  return false;
}

static bool wordPrefixIgnoreCase(const char *text, const char *query) {
  if (!text || !query || !query[0])
    return false;

  if (startsWithIgnoreCase(text, query))
    return true;

  for (size_t i = 1; text[i]; i++) {
    if (text[i - 1] == ' ' && startsWithIgnoreCase(&text[i], query))
      return true;
  }
  return false;
}

static bool tokenLooksValid(const char *token) {
  if (!token || strlen(token) != TOKEN_HEX_LEN)
    return false;

  for (size_t i = 0; token[i]; i++) {
    if (!isxdigit((unsigned char)token[i]))
      return false;
  }
  return true;
}

static int compareContacts(const void *lhs, const void *rhs) {
  const DmContact *a = (const DmContact *)lhs;
  const DmContact *b = (const DmContact *)rhs;

  if (a->lastActive < b->lastActive)
    return 1;
  if (a->lastActive > b->lastActive)
    return -1;

  if (a->nickname[0] && !b->nickname[0])
    return -1;
  if (!a->nickname[0] && b->nickname[0])
    return 1;

  if (a->nickname[0] && b->nickname[0]) {
    int nickCmp = strcasecmp(a->nickname, b->nickname);
    if (nickCmp != 0)
      return nickCmp;
  }

  return strcmp(a->token, b->token);
}

static int compareMatches(const void *lhs, const void *rhs) {
  const RankedContactMatch *a = (const RankedContactMatch *)lhs;
  const RankedContactMatch *b = (const RankedContactMatch *)rhs;

  if (a->score < b->score)
    return 1;
  if (a->score > b->score)
    return -1;
  if (a->lastActive < b->lastActive)
    return 1;
  if (a->lastActive > b->lastActive)
    return -1;
  if (a->index > b->index)
    return 1;
  if (a->index < b->index)
    return -1;
  return 0;
}

static int findNicknameExact(const ContactBook *book, const char *nickname) {
  if (!book || !nickname || !nickname[0])
    return -1;

  for (size_t i = 0; i < book->count; i++) {
    if (book->entries[i].nickname[0] &&
        equalsIgnoreCase(book->entries[i].nickname, nickname))
      return (int)i;
  }
  return -1;
}

static int ensureContact(ContactBook *book, const char *token) {
  if (!book || !token || !token[0])
    return -1;

  int idx = contactsFindByToken(book, token);
  if (idx >= 0)
    return idx;

  if (book->count >= MAX_DM_CONTACTS)
    return -1;

  idx = (int)book->count++;
  memset(&book->entries[idx], 0, sizeof(book->entries[idx]));
  snprintf(book->entries[idx].token, sizeof(book->entries[idx].token), "%s",
           token);
  return idx;
}

static void sortContacts(ContactBook *book) {
  if (!book || book->count < 2)
    return;
  qsort(book->entries, book->count, sizeof(book->entries[0]), compareContacts);
}

static size_t trimSpaces(const char *input, char *out, size_t outSize) {
  if (!out || outSize == 0)
    return 0;

  out[0] = '\0';
  if (!input)
    return 0;

  while (*input == ' ')
    input++;

  size_t len = strlen(input);
  while (len > 0 && input[len - 1] == ' ')
    len--;

  if (len >= outSize)
    len = outSize - 1;
  memcpy(out, input, len);
  out[len] = '\0';
  return len;
}

static int matchScore(const DmContact *contact, const char *query) {
  if (!contact || !query || !query[0])
    return 0;

  if (contact->nickname[0]) {
    if (equalsIgnoreCase(contact->nickname, query))
      return CONTACT_SCORE_NICK_EXACT;
    if (startsWithIgnoreCase(contact->nickname, query))
      return CONTACT_SCORE_NICK_PREFIX;
    if (wordPrefixIgnoreCase(contact->nickname, query))
      return CONTACT_SCORE_NICK_WORD;
    if (containsIgnoreCase(contact->nickname, query))
      return CONTACT_SCORE_NICK_SUBSTRING;
  }

  if (equalsIgnoreCase(contact->token, query))
    return CONTACT_SCORE_TOKEN_EXACT;
  if (startsWithIgnoreCase(contact->token, query))
    return CONTACT_SCORE_TOKEN_PREFIX;
  if (strlen(query) >= 4 && containsIgnoreCase(contact->token, query))
    return CONTACT_SCORE_TOKEN_SUBSTRING;

  return 0;
}

size_t contactsLoad(ContactBook *book) {
  if (!book)
    return 0;

  memset(book, 0, sizeof(*book));

  HistoryDmEntry historyEntries[MAX_DM_CONTACTS];
  size_t historyCount = historyLoadEntries(historyEntries, MAX_DM_CONTACTS);
  for (size_t i = 0; i < historyCount; i++) {
    int idx = ensureContact(book, historyEntries[i].token);
    if (idx >= 0)
      book->entries[idx].lastActive = historyEntries[i].lastActive;
  }

  DmNickEntry nickEntries[MAX_DM_CONTACTS];
  size_t nickCount = identityLoadDmNickEntries(nickEntries, MAX_DM_CONTACTS);
  for (size_t i = 0; i < nickCount; i++) {
    int idx = ensureContact(book, nickEntries[i].token);
    if (idx >= 0) {
      snprintf(book->entries[idx].nickname,
               sizeof(book->entries[idx].nickname), "%s", nickEntries[i].nick);
    }
  }

  sortContacts(book);
  return book->count;
}

bool contactsSaveNicknames(const ContactBook *book) {
  if (!book)
    return false;

  DmNickEntry entries[MAX_DM_CONTACTS];
  size_t count = 0;
  for (size_t i = 0; i < book->count && count < MAX_DM_CONTACTS; i++) {
    if (!book->entries[i].token[0] || !book->entries[i].nickname[0])
      continue;
    snprintf(entries[count].token, sizeof(entries[count].token), "%s",
             book->entries[i].token);
    snprintf(entries[count].nick, sizeof(entries[count].nick), "%s",
             book->entries[i].nickname);
    count++;
  }
  return identitySaveDmNickEntries(entries, count);
}

bool contactsRememberToken(ContactBook *book, const char *token) {
  if (!book || !tokenLooksValid(token))
    return false;

  int idx = ensureContact(book, token);
  if (idx < 0)
    return false;

  book->entries[idx].lastActive = time(NULL);
  sortContacts(book);
  return true;
}

int contactsFindByToken(const ContactBook *book, const char *token) {
  if (!book || !token || !token[0])
    return -1;

  for (size_t i = 0; i < book->count; i++) {
    if (strcmp(book->entries[i].token, token) == 0)
      return (int)i;
  }
  return -1;
}

const DmContact *contactsGet(const ContactBook *book, size_t index) {
  if (!book || index >= book->count)
    return NULL;
  return &book->entries[index];
}

void contactsFormatLabel(const ContactBook *book, const char *token, char *out,
                         size_t outSize) {
  if (!out || outSize == 0)
    return;

  out[0] = '\0';
  if (!token || !token[0]) {
    snprintf(out, outSize, "none");
    return;
  }

  int idx = contactsFindByToken(book, token);
  if (idx >= 0 && book->entries[idx].nickname[0]) {
    snprintf(out, outSize, "%s", book->entries[idx].nickname);
    return;
  }

  snprintf(out, outSize, "%.12s", token);
}

void contactsFormatReference(const ContactBook *book, size_t index, char *out,
                             size_t outSize) {
  if (!out || outSize == 0)
    return;

  const DmContact *contact = contactsGet(book, index);
  if (!contact) {
    snprintf(out, outSize, "unknown");
    return;
  }

  if (contact->nickname[0]) {
    snprintf(out, outSize, "%s (%.12s)", contact->nickname, contact->token);
  } else {
    snprintf(out, outSize, "%.12s", contact->token);
  }
}

bool contactsNormalizeNickname(const char *input, char *out, size_t outSize) {
  if (!out || outSize == 0)
    return false;

  out[0] = '\0';
  if (!input)
    return false;

  char trimmed[MAX_NAME_LEN];
  trimSpaces(input, trimmed, sizeof(trimmed));
  if (!trimmed[0])
    return false;

  size_t len = 0;
  bool lastWasSpace = false;
  for (size_t i = 0; trimmed[i]; i++) {
    unsigned char ch = (unsigned char)trimmed[i];
    if (ch == ' ') {
      if (lastWasSpace)
        continue;
      if (len + 1 >= outSize)
        return false;
      out[len++] = ' ';
      lastWasSpace = true;
      continue;
    }

    lastWasSpace = false;
    if (!(isalnum(ch) || ch == '-' || ch == '_' || ch == '.' || ch == '\'' ||
          ch == '@'))
      return false;
    if (len + 1 >= outSize)
      return false;
    out[len++] = (char)ch;
  }

  while (len > 0 && out[len - 1] == ' ')
    len--;
  out[len] = '\0';
  return len > 0;
}

bool contactsSetNickname(ContactBook *book, const char *token, const char *nickname,
                         char *errorOut, size_t errorSize) {
  if (errorOut && errorSize > 0)
    errorOut[0] = '\0';

  if (!book || !tokenLooksValid(token)) {
    if (errorOut && errorSize > 0)
      snprintf(errorOut, errorSize, "Invalid contact token");
    return false;
  }

  char normalized[MAX_NAME_LEN];
  if (!contactsNormalizeNickname(nickname, normalized, sizeof(normalized))) {
    if (errorOut && errorSize > 0)
      snprintf(errorOut, errorSize,
               "Nicknames may use letters, digits, spaces, ., -, _, ', and @");
    return false;
  }

  for (size_t i = 0; i < book->count; i++) {
    if (strcmp(book->entries[i].token, token) != 0 &&
        book->entries[i].nickname[0] &&
        equalsIgnoreCase(book->entries[i].nickname, normalized)) {
      if (errorOut && errorSize > 0)
        snprintf(errorOut, errorSize, "Nickname already belongs to another contact");
      return false;
    }
  }

  int idx = ensureContact(book, token);
  if (idx < 0) {
    if (errorOut && errorSize > 0)
      snprintf(errorOut, errorSize, "Contact list is full");
    return false;
  }

  snprintf(book->entries[idx].nickname, sizeof(book->entries[idx].nickname),
           "%s", normalized);
  sortContacts(book);
  return true;
}

bool contactsClearNickname(ContactBook *book, const char *token) {
  int idx = contactsFindByToken(book, token);
  if (idx < 0)
    return false;

  book->entries[idx].nickname[0] = '\0';
  sortContacts(book);
  return true;
}

size_t contactsSearch(const ContactBook *book, const char *query,
                      ContactMatch *matches, size_t maxMatches) {
  if (!book || !matches || maxMatches == 0)
    return 0;

  char trimmed[128];
  trimSpaces(query, trimmed, sizeof(trimmed));
  if (!trimmed[0])
    return 0;

  RankedContactMatch ranked[MAX_DM_CONTACTS];
  size_t rankedCount = 0;
  for (size_t i = 0; i < book->count; i++) {
    int score = matchScore(&book->entries[i], trimmed);
    if (score <= 0)
      continue;
    ranked[rankedCount].index = i;
    ranked[rankedCount].score = score;
    ranked[rankedCount].lastActive = book->entries[i].lastActive;
    rankedCount++;
  }

  qsort(ranked, rankedCount, sizeof(ranked[0]), compareMatches);

  size_t copied = rankedCount < maxMatches ? rankedCount : maxMatches;
  for (size_t i = 0; i < copied; i++) {
    matches[i].index = ranked[i].index;
    matches[i].score = ranked[i].score;
  }
  return copied;
}

ContactLookupStatus contactsLookup(const ContactBook *book, const char *query,
                                   ContactMatch *matches, size_t maxMatches,
                                   size_t *matchCount) {
  if (matchCount)
    *matchCount = 0;
  if (!book || !query)
    return CONTACT_LOOKUP_NONE;

  char trimmed[128];
  trimSpaces(query, trimmed, sizeof(trimmed));
  if (!trimmed[0])
    return CONTACT_LOOKUP_NONE;

  bool numeric = true;
  for (size_t i = 0; trimmed[i]; i++) {
    if (!isdigit((unsigned char)trimmed[i])) {
      numeric = false;
      break;
    }
  }
  if (numeric) {
    long index = strtol(trimmed, NULL, 10);
    if (index >= 1 && (size_t)index <= book->count) {
      if (matches && maxMatches > 0) {
        matches[0].index = (size_t)index - 1;
        matches[0].score = CONTACT_SCORE_NICK_EXACT;
      }
      if (matchCount)
        *matchCount = 1;
      return CONTACT_LOOKUP_UNIQUE;
    }
  }

  int exactNick = findNicknameExact(book, trimmed);
  if (exactNick >= 0) {
    if (matches && maxMatches > 0) {
      matches[0].index = (size_t)exactNick;
      matches[0].score = CONTACT_SCORE_NICK_EXACT;
    }
    if (matchCount)
      *matchCount = 1;
    return CONTACT_LOOKUP_UNIQUE;
  }

  int exactToken = contactsFindByToken(book, trimmed);
  if (exactToken >= 0) {
    if (matches && maxMatches > 0) {
      matches[0].index = (size_t)exactToken;
      matches[0].score = CONTACT_SCORE_TOKEN_EXACT;
    }
    if (matchCount)
      *matchCount = 1;
    return CONTACT_LOOKUP_UNIQUE;
  }

  size_t found = contactsSearch(book, trimmed, matches, maxMatches);
  if (matchCount)
    *matchCount = found;
  if (found == 0)
    return CONTACT_LOOKUP_NONE;
  if (found == 1)
    return CONTACT_LOOKUP_UNIQUE;
  return CONTACT_LOOKUP_AMBIGUOUS;
}
