#pragma once
#ifndef CONTACTS_H
#define CONTACTS_H

#include "history.h"
#include "identity.h"

#include <stdbool.h>
#include <stddef.h>

#define MAX_DM_CONTACTS 128

typedef struct {
    char token[TOKEN_STR_SIZE];
    char nickname[MAX_NAME_LEN];
    time_t lastActive;
} DmContact;

typedef struct {
    DmContact entries[MAX_DM_CONTACTS];
    size_t count;
} ContactBook;

typedef struct {
    size_t index;
    int score;
} ContactMatch;

typedef enum {
    CONTACT_LOOKUP_NONE,
    CONTACT_LOOKUP_UNIQUE,
    CONTACT_LOOKUP_AMBIGUOUS
} ContactLookupStatus;

size_t contactsLoad(ContactBook *book);
bool contactsSaveNicknames(const ContactBook *book);
bool contactsRememberToken(ContactBook *book, const char *token);
int contactsFindByToken(const ContactBook *book, const char *token);
const DmContact *contactsGet(const ContactBook *book, size_t index);
void contactsFormatLabel(const ContactBook *book, const char *token, char *out,
                         size_t outSize);
void contactsFormatReference(const ContactBook *book, size_t index, char *out,
                             size_t outSize);
bool contactsNormalizeNickname(const char *input, char *out, size_t outSize);
bool contactsSetNickname(ContactBook *book, const char *token, const char *nickname,
                         char *errorOut, size_t errorSize);
bool contactsClearNickname(ContactBook *book, const char *token);
size_t contactsSearch(const ContactBook *book, const char *query,
                      ContactMatch *matches, size_t maxMatches);
ContactLookupStatus contactsLookup(const ContactBook *book, const char *query,
                                   ContactMatch *matches, size_t maxMatches,
                                   size_t *matchCount);

#endif
