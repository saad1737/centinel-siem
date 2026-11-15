// This is the log follower component that follows log files and dumps linux logs to the CWEB engine

#ifndef LOG_FOLLOWER_H
#define LOG_FOLLOWER_H

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h> // Linux API to monitor log files
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

/* Buffer large enough for at least several inotify events */
#define EVENT_BUF_LEN (256 * (sizeof(struct inotify_event) + NAME_MAX + 1))
#define MAX_PATH_LEN 256
#define MAX_NAME_LEN 128
#define MAX_BUF_LEN 2048
#define MAX_CHUNK_LEN 8192

typedef struct {
    char dir_path[MAX_PATH_LEN]; // path to the directory where the file resides
    char file_path[MAX_PATH_LEN]; // path to the file to be tracked
    char file_name[MAX_NAME_LEN]; // name of the file to be tracked
    int fd; // file descriptor of the tracked file (must default to -1)
    int dir_wd; // watch descriptor of the tracked file's directory (must default to -1)
    int file_wd; // watch descriptor of the tracked file for monitoring (must default to -1)
    off_t offset; // the current byte position we have processed upto
    ino_t inode; // inode number for detecting file renaming
    char buffer[MAX_BUF_LEN]; // buffer to store partial lines across reads
} Trackedfile;

void drain_file(Trackedfile* file); // reads log lines and prints on the terminal for now

#endif
