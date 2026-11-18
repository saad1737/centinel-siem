#ifndef CHECKPOINT_H
#define CHECKPOINT_H

#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdbool.h>

typedef struct {
    dev_t dev; // Device ID
    ino_t inode; // Inode number
    off_t offset; // Last processed byte offset
    time_t last_seen; // Timestamp of last update
} CheckpointEntry;

/* Opens or creates the binary checkpoint file. Returns fd, or -1 on failure */
int checkpoint_open(const char* db_path);

/* Searches the DB for a matching (dev, inode).
 Returns 0 if found (and populates *out_offset), returns -1 if not found */
int checkpoint_find(int fd, dev_t dev, ino_t inode, off_t* out_offset);

/* Updates an existing entry, or appends a new entry at EOF if not found.
 Returns 0 on success, -1 on failure */
int checkpoint_save(int fd, dev_t dev, ino_t inode, off_t offset);

/* Flushes and closes the DB */
void checkpoint_close(int fd);

#endif
