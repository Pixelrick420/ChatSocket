#pragma once
#ifndef HISTORY_H
#define HISTORY_H

#include <stdbool.h>
#include <stddef.h>
#include <dirent.h>
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MAX_LINE 2048
#define TOKEN_STR_SIZE 65

bool historyAppend(const char *peerToken, bool sent, const char *message);
void historyPrint(const char *peerToken, size_t count);
bool historyExists(const char *peerToken);
void historyListAll(void);

#endif
