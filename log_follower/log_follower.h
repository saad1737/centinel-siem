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

#define WATCH_DIR   "/tmp"
#define TARGET_FILE "text.log"
#define FULL_PATH   WATCH_DIR "/" TARGET_FILE

/* Buffer large enough for at least several inotify events */
#define EVENT_BUF_LEN (16 * (sizeof(struct inotify_event) + NAME_MAX + 1))

#endif
