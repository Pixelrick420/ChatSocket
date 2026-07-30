#ifndef SESSION_H
#define SESSION_H

#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/**
 * Initialize the session counter by loading from a binary file.
 * If the file doesn't exist, creates it with counter = 0.
 *
 * @param counterFilePath Path to the binary counter file
 * @return true on success, false on failure
 */
bool sessionCounterInit(const char *counterFilePath);

/**
 * Increment the session counter and persist to disk.
 *
 * @return The new counter value, or 0 on error
 */
uint64_t sessionCounterIncrement(void);

/**
 * Get the current counter value without incrementing.
 *
 * @return The current counter value, or 0 if not initialized
 */
uint64_t sessionCounterGet(void);

/**
 * Clean up session counter resources.
 */
void sessionCounterCleanup(void);

#endif /* SESSION_COUNTER_H */
