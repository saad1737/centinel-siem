#include "checkpoint.h"

int checkpoint_open(const char* db_path) {
    if (!db_path) return -1;

    int fd = open(db_path, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
    if (fd < 0) {
        perror("checkpoint open failed");
        return -1;
    }

    return fd;
}

int checkpoint_find(int fd, dev_t dev, ino_t inode, off_t* out_offset) {
    off_t pos = 0;
    CheckpointEntry entry;
    ssize_t bytes;

    point:
    // pread to read the checkpoint entry without modifying the file cursor
    bytes = pread(fd, &entry, sizeof(CheckpointEntry), pos);
    if (bytes <= 0) { // reached EOF without finding a match
        return -1;
    }

    if (bytes == sizeof(CheckpointEntry)) { // found an entry
        if (entry.dev == dev && entry.inode == inode) { // Match found. Copy offset
            *out_offset = entry.offset;
            return 0; // success
        }
    }

    // advance pos to the next entry and repeat
    pos += sizeof(CheckpointEntry);
    goto point;

    return 0;
}

int checkpoint_save(int fd, dev_t dev, ino_t inode, off_t offset) {
    off_t pos = 0;
    CheckpointEntry entry;

    // scan through the file to see if the entry already exists
    while (pread(fd, &entry, sizeof(CheckpointEntry), pos) == sizeof(CheckpointEntry)) {
        if (entry.dev == dev && entry.inode == inode) {
            // Found existing entry! Update fields in place:
            entry.offset = offset;
            entry.last_seen = time(NULL);
            ssize_t written = pwrite(fd, &entry, sizeof(CheckpointEntry), pos);
            return (written == sizeof(CheckpointEntry)) ? 0 : -1;
        }
        pos += sizeof(CheckpointEntry);
    }

    // entry not found path
    // write a new entry at pos which is now at EOF
    CheckpointEntry new_entry;
    new_entry.dev = dev;
    new_entry.inode = inode;
    new_entry.last_seen = time(NULL);
    new_entry.offset = offset;

    // write at EOF
    ssize_t written = pwrite(fd, &new_entry, sizeof(CheckpointEntry), pos);
    return (written == sizeof(CheckpointEntry)) ? 0 : -1;
}

void checkpoint_close(int fd) {
    if (fd >= 0) {
        fsync(fd); // ensures all writes hit physical disk
        close(fd);
    }
}
