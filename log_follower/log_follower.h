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
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#include "hashmap.h"
#include "checkpoint.h"
#include "chunk_queue.h"
#include "ws_client.h"

/* Buffer large enough for at least several inotify events */
#define EVENT_BUF_LEN (256 * (sizeof(struct inotify_event) + NAME_MAX + 1))
#define MAX_PATH_LEN 256
#define MAX_NAME_LEN 128
#define MAX_BUF_LEN 2048
#define MAX_CHUNK_LEN 8192
#define CHUNK_CAPACITY (12 * 1024) // 12 KB chunk threshold
#define CHECKPOINT_DB_PATH "/tmp/sentinel_checkpoint.db"
#define MAX_EPOLL_EVENTS 16
#define FLUSH_INTERVAL_MS 500 // timer ticks every 500 ms

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
    char buffer[MAX_CHUNK_LEN]; // buffer to carry partial line chunks
    size_t buf_len; // size of chunk present in the buffer
} Trackedfile;

typedef struct {
    char dir_path[MAX_PATH_LEN]; // path to the directory where the file resides
    int dir_wd; // watch descriptor of the directory of the tracked file/s (must default to -1)
    int ref_count; // number of files being monitored in this directory
} TrackedDir;

typedef struct LogChunk {
    char* data; // Pre-allocated contiguous byte buffer
    size_t capacity; // Maximum size (e.g. 16384 bytes)
    size_t length; // Current number of bytes written
    size_t record_count; // Total log lines stored in this chunk
    time_t created_at; // Timestamp when chunk was created (for time-based flush)
} LogChunk;

typedef struct {
    int inotify_fd; // the master inotify instance
    int checkpoint_fd; // file descriptor to sentinel_checkpoint.db
    int epoll_fd; // the master epoll instance
    int timer_fd; // periodic timer file descriptor
    LogChunk* active_chunk; // to process the log chunk arrived by the read call
    HashMap* files_by_wd; // Maps "wd:<int>" → Trackedfile* -> immediately grab the file upon IN_MODIFY
    HashMap* files_by_path; // Maps full path "/var/log/auth.log" → Trackedfile* -> used for dir events telling a file appeared or disappeared
    HashMap* dirs_by_wd; //  Maps "dir:<int>" → TrackedDir* -> immediately grab the directory upon a dir event
    HashMap* dirs_by_path; // Maps full path "/var/log" → TrackedDir* -> used when adding a new file target to follow
    ChunkQueue queue; // in-memory queue of sealed chunks ready to be sent
    bool is_paused; // disk backpressure state (true = pause file reads)
    WsClient ws; // websocket client context of the log follower
} FollowerContext;

/* Lifecycle for Trackedfile */
Trackedfile* tracked_file_create(const char* full_path);
void tracked_file_destroy(Trackedfile* file);

/* Lifecycle for TrackedDir */
TrackedDir* tracked_dir_create(const char* dir_path);
void tracked_dir_destroy(TrackedDir* dir);

/* Lifecycle for LogChunk */
LogChunk* log_chunk_create(size_t capacity);
void log_chunk_destroy(LogChunk* lc);
int log_chunk_append(LogChunk* lc, const char* record, size_t record_len); // returns 0 for success, 1 for chunk full, -1 for any other errors
void log_chunk_flush(LogChunk* lc);

/* Engine Context */
FollowerContext* follower_init(void);
void follower_destroy(FollowerContext* ctx);

/* Target Registration */
int follower_add_target(FollowerContext* ctx, const char* file_path);

/* Chunk sealing */
void follower_seal_active_chunk(FollowerContext* ctx);

/* Catch up routine after backpressure releases */
void follower_catchup_all(FollowerContext* ctx);

/* Consumer Routine */
size_t follower_drain_queue(FollowerContext* ctx, size_t max_chunks); // max_chunks = 0 -> drain all available chunks

/* Helpers */
void json_escape_string(const char* src, char* dest, size_t max_len);
void drain_file(FollowerContext* ctx, Trackedfile* file); // reads log lines and prints on the terminal for now

#endif
