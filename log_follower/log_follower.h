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

#include "hashmap.h"

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
    int file_wd; // watch descriptor of the tracked file for monitoring (must default to -1)
    off_t offset; // the current byte position we have processed upto
    ino_t inode; // inode number for detecting file renaming
    dev_t dev; // device ID
    bool is_active; // whether the file exists currently on disk
} Trackedfile;

typedef struct {
    char dir_path[MAX_PATH_LEN]; // path to the directory where the file resides
    int dir_wd; // watch descriptor of the directory of the tracked file/s (must default to -1)
    int ref_count; // number of files being monitored in this directory
} TrackedDir;

typedef struct {
    int inotify_fd; // the master inotify instance
    HashMap* files_by_wd; // Maps "wd:<int>" → Trackedfile* -> immediately grab the file upon IN_MODIFY
    HashMap* files_by_path; // Maps full path "/var/log/auth.log" → Trackedfile* -> used for dir events telling a file appeared or disappeared
    HashMap* dirs_by_wd; //  Maps "dir:<int>" → TrackedDir* -> immediately grab the directory upon a dir event
    HashMap* dirs_by_path; // Maps full path "/var/log" → TrackedDir* -> used when adding a new file target to follow
} FollowerContext;

/* Lifecycle for Trackedfile */
Trackedfile* tracked_file_create(const char* full_path);
void tracked_file_destroy(Trackedfile* file);

/* Lifecycle for TrackedDir */
TrackedDir* tracked_dir_create(const char* dir_path);
void tracked_dir_destroy(TrackedDir* dir);

/* Engine Context */
FollowerContext* follower_init(void);
void follower_destroy(FollowerContext* ctx);

/* Target Registration */
int follower_add_target(FollowerContext* ctx, const char* file_path);

void drain_file(Trackedfile* file); // reads log lines and prints on the terminal for now

#endif
