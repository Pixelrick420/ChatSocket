#pragma once
#ifndef HISTORY_H
#define HISTORY_H

#include "platform.h"

#include <stdbool.h>
#include <stddef.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MAX_LINE 2048
#define TOKEN_STR_SIZE 65

typedef struct {
    char token[TOKEN_STR_SIZE];
    time_t lastActive;
} HistoryDmEntry;

bool historyAppend(const char *peerToken, bool sent, const char *message);
void historyPrint(const char *peerToken, size_t count);
bool historyExists(const char *peerToken);
void historyListAll(void);
size_t historyLoadEntries(HistoryDmEntry *entries, size_t maxEntries);
int historyGetAll(char tokens[][TOKEN_STR_SIZE], size_t maxTokens);

#endif
