#include "log_follower.h"

static volatile sig_atomic_t keep_running = 1;

static void handle_sigint(int sig) {
    (void)sig;
    keep_running = 0;
}

/* Reads and prints any new bytes appended to the open file stream */
static void drain_new_lines(FILE **fp) {
    if (!*fp) {
        return;
    }

    char line[4096];
    clearerr(*fp);

    while (fgets(line, sizeof(line), *fp) != NULL) {
        fputs(line, stdout);
    }
    fflush(stdout);
}

/* Opens (or re-opens) the target file and seeks to the end */
static void open_target_file(FILE **fp, bool seek_end) {
    if (*fp) {
        fclose(*fp);
        *fp = NULL;
    }

    *fp = fopen(FULL_PATH, "r");
    if (!*fp) {
        if (errno != ENOENT) {
            perror("fopen");
        }
        return;
    }

    if (seek_end) {
        fseek(*fp, 0, SEEK_END);
    }
}

int main(void) {
    /* Graceful exit on Ctrl+C */
    struct sigaction sa = {0};
    sa.sa_handler = handle_sigint;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    int inotify_fd = inotify_init1(IN_CLOEXEC);
    if (inotify_fd < 0) {
        perror("inotify_init1");
        return EXIT_FAILURE;
    }

    /* Watch the directory so we catch modifications, creation, and deletion */
    uint32_t watch_mask = IN_MODIFY | IN_CREATE | IN_MOVED_TO | IN_DELETE | IN_MOVED_FROM;
    int watch_fd = inotify_add_watch(inotify_fd, WATCH_DIR, watch_mask);
    if (watch_fd < 0) {
        perror("inotify_add_watch");
        close(inotify_fd);
        return EXIT_FAILURE;
    }

    /* Open the file if it already exists and jump to the end (like tail -f) */
    FILE *target_fp = NULL;
    open_target_file(&target_fp, true);

    printf("Monitoring %s for changes... (Press Ctrl+C to stop)\n", FULL_PATH);

    /* Align buffer properly for struct inotify_event */
    char buf[EVENT_BUF_LEN] __attribute__((aligned(__alignof__(struct inotify_event))));

    while (keep_running) {
        ssize_t len = read(inotify_fd, buf, sizeof(buf));
        if (len < 0) {
            if (errno == EINTR) {
                continue; /* Interrupted by signal; loop checks keep_running */
            }
            perror("read");
            break;
        }

        for (char *ptr = buf; ptr < buf + len; ) {
            struct inotify_event *event = (struct inotify_event *)ptr;

            /* Filter strictly for events matching "text.log" */
            if (event->len > 0 && strcmp(event->name, TARGET_FILE) == 0) {
                if (event->mask & (IN_CREATE | IN_MOVED_TO)) {
                    /* File was just created or moved into /tmp; read from start */
                    open_target_file(&target_fp, false);
                    drain_new_lines(&target_fp);
                }
                else if (event->mask & IN_MODIFY) {
                    if (!target_fp) {
                        open_target_file(&target_fp, false);
                    }
                    else {
                        /* Handle file truncation (e.g., `> /tmp/text.log`) */
                        struct stat st;
                        if (fstat(fileno(target_fp), &st) == 0 && st.st_size < ftell(target_fp)) {
                            rewind(target_fp);
                        }
                    }
                    drain_new_lines(&target_fp);
                }
                else if (event->mask & (IN_DELETE | IN_MOVED_FROM)) {
                    if (target_fp) {
                        fclose(target_fp);
                        target_fp = NULL;
                    }
                }
            }

            ptr += sizeof(struct inotify_event) + event->len;
        }
    }

    if (target_fp) {
        fclose(target_fp);
    }
    inotify_rm_watch(inotify_fd, watch_fd);
    close(inotify_fd);

    printf("\nStopped monitoring.\n");
    return EXIT_SUCCESS;
}
