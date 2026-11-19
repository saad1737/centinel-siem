#include "log_follower.h"

static volatile sig_atomic_t keep_running = 1;

static void handle_sigint(int sig) {
    (void)sig;
    keep_running = 0;
}

void json_escape_string(const char* src, char* dest, size_t max_len) {
    if (!src || !dest || max_len == 0) return;

    size_t i = 0, j = 0;
    while (src[i] != '\0' && j + 1 < max_len) {
        switch (src[i]) {
            case '"':  if (j + 2 < max_len) { dest[j++] = '\\'; dest[j++] = '"'; } else goto done; break;
            case '\\': if (j + 2 < max_len) { dest[j++] = '\\'; dest[j++] = '\\'; } else goto done; break;
            case '\n': if (j + 2 < max_len) { dest[j++] = '\\'; dest[j++] = 'n'; } else goto done; break;
            case '\r': if (j + 2 < max_len) { dest[j++] = '\\'; dest[j++] = 'r'; } else goto done; break;
            case '\t': if (j + 2 < max_len) { dest[j++] = '\\'; dest[j++] = 't'; } else goto done; break;
            default:
                if ((unsigned char)src[i] >= 0x20) {
                    dest[j++] = src[i];
                }
                break;
        }
        i++;
    }
    done:
    dest[j] = '\0';
}

void drain_file(FollowerContext* ctx, Trackedfile* file) {
    if (!ctx || !file || ctx->is_paused || !ctx->active_chunk) return;

    while (1) {
        // Calculate how much space is left in file->buffer
        size_t space_avail = sizeof(file->buffer) - file->buf_len;

        // Handle giant line edge case (> 8 KB without '\n')
        if (space_avail == 0) {
            // Buffer is full with no newline. Flush the whole buffer as a line to avoid stalling!
            char escaped_msg[MAX_CHUNK_LEN * 2];
            char temp_line[MAX_CHUNK_LEN + 1];
            memcpy(temp_line, file->buffer, file->buf_len);
            temp_line[file->buf_len] = '\0';

            json_escape_string(temp_line, escaped_msg, sizeof(escaped_msg));

            char record[MAX_CHUNK_LEN * 2 + 128];
            int rec_len = snprintf(record, sizeof(record),
                                   "{\"ts\":%ld,\"file\":\"%s\",\"msg\":\"%s\"}\n",
                                   (long)time(NULL), file->file_name, escaped_msg);

            if (log_chunk_append(ctx->active_chunk, record, (size_t)rec_len) == 1) {
                follower_seal_active_chunk(ctx);
                log_chunk_append(ctx->active_chunk, record, (size_t)rec_len);
            }

            file->offset += file->buf_len;
            file->buf_len = 0;
            space_avail = sizeof(file->buffer);
        }

        // Read new bytes directly after any leftover bytes
        ssize_t bytes_read = read(file->fd, file->buffer + file->buf_len, space_avail);
        if (bytes_read <= 0) {
            // EOF or no more data to read right now
            break;
        }

        size_t total_bytes = file->buf_len + (size_t)bytes_read;
        size_t start = 0;

        // Forward scan looking for '\n'
        for (size_t i = 0; i < total_bytes; i++) {
            if (file->buffer[i] == '\n') {
                size_t line_len = i - start;

                // Strip trailing '\r' if present
                if (line_len > 0 && file->buffer[start + line_len - 1] == '\r') {
                    line_len--;
                }

                // Copy line and null-terminate
                char line_buf[MAX_CHUNK_LEN];
                if (line_len >= sizeof(line_buf)) line_len = sizeof(line_buf) - 1;
                memcpy(line_buf, file->buffer + start, line_len);
                line_buf[line_len] = '\0';

                // Escape JSON special characters
                char escaped_msg[MAX_CHUNK_LEN * 2];
                json_escape_string(line_buf, escaped_msg, sizeof(escaped_msg));

                // Format NDJSON record
                char record[MAX_CHUNK_LEN * 2 + 128];
                int rec_len = snprintf(record, sizeof(record),
                                       "{\"ts\":%ld,\"file\":\"%s\",\"msg\":\"%s\"}\n",
                                       (long)time(NULL), file->file_name, escaped_msg);

                // Append into active chunk (seal chunk if full)
                if (log_chunk_append(ctx->active_chunk, record, (size_t)rec_len) == 1) {
                    follower_seal_active_chunk(ctx);
                    log_chunk_append(ctx->active_chunk, record, (size_t)rec_len);
                }

                start = i + 1;
            }
        }

        // Update file offset with consumed bytes
        file->offset += start;

        // save the new offset to disk
        if (start > 0) {
            checkpoint_save(ctx->checkpoint_fd, file->dev, file->inode, file->offset);
        }

        // Slide leftover partial line to the front of file->buffer
        size_t leftover = total_bytes - start;
        if (leftover > 0) {
            memmove(file->buffer, file->buffer + start, leftover);
            file->buf_len = leftover;
        }
        else {
            file->buf_len = 0;
        }

        // Check for backpressure
        if (ctx->is_paused) break;

        // If we read less than the buffer capacity and consumed nothing new, we've hit EOF
        if (bytes_read < (ssize_t)space_avail && start == 0) {
            break;
        }
    }
}

int main(void) {
    // signal/interrupt handler setup
    /* Graceful exit on Ctrl+C */
    struct sigaction sa = {0};
    sa.sa_handler = handle_sigint;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    // initialize the follower contex
    FollowerContext* ctx = follower_init();
    if (!ctx) {
        fprintf(stderr, "Follower Context creation failed\n");
    }

    // add files to monitor one by one (testing)
    follower_add_target(ctx, "/tmp/test1.log");
    follower_add_target(ctx, "/tmp/test2.log");

    // declare an event buffer
    char event_buf[EVENT_BUF_LEN] __attribute__((aligned(__alignof__(struct inotify_event)))); // aligning packing is critical
    struct epoll_event events[MAX_EPOLL_EVENTS];
    while (keep_running) {
        int nfds = epoll_wait(ctx->epoll_fd, events, MAX_EPOLL_EVENTS, -1);
        if (nfds < 0) {
            if (errno == EINTR) continue; // Signal received (Ctrl+C), loop checks keep_running
            perror("epoll_wait failed");
            break;
        }

        // dispatch all ready descriptors
        for (int i = 0; i < nfds; i++) {

            // Case 1: Periodic Timer Fired (every 500ms)
            if (events[i].data.fd == ctx->timer_fd) {
                // Drain the timer tick (reading 8-byte uint64_t acknowledges the timer to the kernel)
                uint64_t expirations;
                ssize_t s = read(ctx->timer_fd, &expirations, sizeof(expirations));
                (void)s;

                // Periodic Seal: Seal any buffered logs so they don't sit in memory
                if (ctx->active_chunk && ctx->active_chunk->length > 0) {
                    follower_seal_active_chunk(ctx);
                }
                // call follower drain
                follower_drain_queue(ctx, 4); // drain upto 4 chunks per 500ms tick
            }

            // Case 2: Inotify File Events Fired
            else if (events[i].data.fd == ctx->inotify_fd) {
                ssize_t num_read = read(ctx->inotify_fd, event_buf, sizeof(event_buf));
                if (num_read < 0) {
                    if (errno == EINTR) continue;
                    perror("inotify read failed");
                    break;
                }

                // Process inotify event stream (Branch A & Branch B, exactly as you have it now!)
                for (char* ptr = event_buf; ptr < event_buf + num_read; ) {
                    struct inotify_event* event = (struct inotify_event*)ptr;

                    char file_key[256];
                    snprintf(file_key, sizeof(file_key), "wd:%d", event->wd);

                    char dir_key[256];
                    snprintf(dir_key, sizeof(dir_key), "dir:%d", event->wd);

                    // Check if this is a File Event
                    Trackedfile* file = (Trackedfile*)hashmap_get(ctx->files_by_wd, file_key);
                    if (file) {
                        if (event->mask & IN_MODIFY) {
                            struct stat st;
                            if (fstat(file->fd, &st) == 0) {
                                if (st.st_size < file->offset) {
                                    file->offset = 0;
                                    lseek(file->fd, 0, SEEK_SET);
                                    checkpoint_save(ctx->checkpoint_fd, file->dev, file->inode, 0);
                                }
                            }
                            else {
                                perror("fstat failed during truncation check");
                            }
                            drain_file(ctx, file);
                        }
                        else if (event->mask & (IN_DELETE_SELF | IN_MOVE_SELF)) {
                            // File moved or unlinked
                            drain_file(ctx, file);
                            inotify_rm_watch(ctx->inotify_fd, file->file_wd);
                            hashmap_remove(ctx->files_by_wd, file_key);
                            file->file_wd = -1;
                            close(file->fd);
                            file->fd = -1;
                            file->is_active = false;
                        }
                    }
                    // Check if this is a Directory Event
                    else {
                        TrackedDir* dir = (TrackedDir*)hashmap_get(ctx->dirs_by_wd, dir_key);
                        if (dir && event->len > 0) {
                            // Construct full path of what changed:
                            char full_path[MAX_PATH_LEN * 2];
                            snprintf(full_path, sizeof(full_path), "%s/%s", dir->dir_path, event->name);

                            // Is this a file we are tracking?
                            Trackedfile* target_file = (Trackedfile*)hashmap_get(ctx->files_by_path, full_path);
                            if (target_file) {
                                if (event->mask & (IN_CREATE | IN_MOVED_TO)) {
                                    // File appeared! Open it, attach file_wd, register in files_by_wd, drain!
                                    char key[32];
                                    snprintf(key, sizeof(key), "wd:%d", target_file->file_wd);
                                    hashmap_remove(ctx->files_by_wd, key);

                                    if (target_file->file_wd >= 0) { // clear and reset file watch if exists
                                        inotify_rm_watch(ctx->inotify_fd, target_file->file_wd);
                                        target_file->file_wd = -1;
                                    }

                                    if (target_file->fd >= 0) { // clear and reset file descriptor if exists
                                        close(target_file->fd);
                                        target_file->fd = -1;
                                    }

                                    // try to open the file
                                    struct stat st;
                                    int err;
                                    target_file->fd = open(target_file->file_path, O_RDONLY | O_CLOEXEC);
                                    if (target_file->fd < 0) { // open call failure
                                        if (errno == ENOENT) {
                                            target_file->fd = -1;
                                            target_file->file_wd = -1;
                                            target_file->is_active = false;
                                        }
                                        else {
                                            perror("file open failed");
                                            exit(EXIT_FAILURE);
                                        }
                                    }

                                    if (target_file->fd >= 0) { // open call success
                                        err = fstat(target_file->fd, &st); // read metadata about the file
                                        if (err < 0) {
                                            perror("fstat failed");
                                            tracked_file_destroy(target_file); // dont destroy dir
                                            exit(EXIT_FAILURE);
                                        }

                                        // set inode, dev, offset
                                        target_file->inode = st.st_ino;
                                        target_file->offset = 0;
                                        target_file->dev = st.st_dev;
                                        target_file->is_active = true;

                                        // seek to start (file created new)
                                        lseek(target_file->fd, 0, SEEK_SET);

                                        // save to db
                                        checkpoint_save(ctx->checkpoint_fd, target_file->dev, target_file->inode, 0);

                                        // add file watch
                                        target_file->file_wd = inotify_add_watch(ctx->inotify_fd, target_file->file_path, IN_MODIFY | IN_ATTRIB);
                                        if (target_file->file_wd < 0) { // handle error
                                            perror("File watch failed");
                                            tracked_file_destroy(target_file); // dont destroy dir
                                            exit(EXIT_FAILURE);
                                        }

                                        // register the file wd
                                        char key[32];
                                        snprintf(key, sizeof(key), "wd:%d", target_file->file_wd);
                                        err = hashmap_set(ctx->files_by_wd, key, (void*)target_file);
                                        if (err == -1) {
                                            fprintf(stderr, "Hashmap set failed for file %s\n", target_file->file_path);
                                            tracked_file_destroy(target_file); // dont destroy dir
                                            exit(EXIT_FAILURE);
                                        }

                                        // drain initial lines in the buffer
                                        drain_file(ctx, target_file);
                                    }
                                }
                                else if (event->mask & (IN_DELETE | IN_MOVED_FROM)) {
                                    // Target was deleted from dir! Clean up watch and fd.
                                    char key[32];
                                    snprintf(key, sizeof(key), "wd:%d", target_file->file_wd);
                                    hashmap_remove(ctx->files_by_wd, key);

                                    if (target_file->file_wd >= 0) { // clear and reset file watch if exists
                                        inotify_rm_watch(ctx->inotify_fd, target_file->file_wd);
                                        target_file->file_wd = -1;
                                    }

                                    if (target_file->fd >= 0) { // clear and reset file descriptor if exists
                                        close(target_file->fd);
                                        target_file->fd = -1;
                                    }

                                    target_file->is_active = false;
                                }
                            }
                        }
                    }

                    ptr += sizeof(struct inotify_event) + event->len;
                }
            }
        }
    }

    // cleanup
    follower_destroy(ctx);
    printf("\nStopped monitoring.\n");
    return EXIT_SUCCESS;
}
