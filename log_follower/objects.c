#include "checkpoint.h"
#include "chunk_queue.h"
#include "log_follower.h"
#include <bits/time.h>
#include <bits/types/struct_itimerspec.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>

Trackedfile* tracked_file_create(const char* full_path) {
    // validate path length
    if (strlen(full_path) >= MAX_PATH_LEN) {
        fprintf(stderr, "Path size must be less than %d\n", MAX_PATH_LEN);
        return NULL;
    }

    // find the last slash
    const char* slash = strrchr(full_path, '/');
    const char* name = slash ? (slash + 1) : full_path;

    // validate file name length
    if (strlen(name) >= MAX_NAME_LEN) {
        fprintf(stderr, "File name must be less than %d\n", MAX_NAME_LEN);
        return NULL;
    }

    // allocate memory and handle error
    Trackedfile* file = calloc(1, sizeof(Trackedfile));
    if (!file) {
        perror("tracked_file_create failed");
        return NULL;
    }

    // apply must have default values
    file->fd = -1;
    file->file_wd = -1;
    file->offset = 0;
    file->is_active = false;

    // pointer arithmetic to assign the paths
    if (!slash) { // working directory
        snprintf(file->dir_path, sizeof(file->dir_path), ".");
        snprintf(file->file_name, sizeof(file->file_name), "%s", full_path);
    }
    else if (slash == full_path) { // root of the filesystem
        snprintf(file->dir_path, sizeof(file->dir_path), "/");
        snprintf(file->file_name, sizeof(file->file_name), "%s", slash + 1);
    }
    else {
        size_t dir_len = (size_t)(slash - full_path);
        if (dir_len >= sizeof(file->dir_path)) {
            dir_len = sizeof(file->dir_path) - 1;
        }
        memcpy(file->dir_path, full_path, dir_len);
        file->dir_path[dir_len] = '\0';
        snprintf(file->file_name, sizeof(file->file_name), "%s", slash + 1);
    }
    snprintf(file->file_path, sizeof(file->file_path), "%s", full_path);

    return file;
}

void tracked_file_destroy(Trackedfile* file) {
    if (!file) return;

    // close any opened descriptors first, watch descriptor will already be freed in the upper layer
    if (file->fd >= 0) close(file->fd);
    free(file);
}

TrackedDir* tracked_dir_create(const char* dir_path) {
    // validate path length
    if (strlen(dir_path) >= MAX_PATH_LEN) {
        fprintf(stderr, "Dir Path size must be less than %d\n", MAX_PATH_LEN);
        return NULL;
    }

    // allocate memory and handle error
    TrackedDir* dir = calloc(1, sizeof(TrackedDir));
    if (!dir) {
        perror("tracked_dir_create failed");
        return NULL;
    }

    // apply must have default values
    dir->dir_wd = -1;
    dir->ref_count = 0; // this increments when a file under the directory will be added to follow

    // insert the path string
    snprintf(dir->dir_path, sizeof(dir->dir_path), "%s", dir_path);

    return dir;
}

void tracked_dir_destroy(TrackedDir* dir) {
    if (!dir) return;

    // dir_wd will already be closed in the upper layer
    free(dir);
}

LogChunk* log_chunk_create(size_t capacity) {
    LogChunk* lc = calloc(1, sizeof(LogChunk));
    if (!lc) {
        perror("Log chunk allocation failed");
        return NULL;
    }

    lc->data = malloc(capacity * sizeof(char));
    if (!lc->data) {
        perror("Log chunk data allocation failed");
        free(lc);
        return NULL;
    }

    lc->capacity = capacity; // default
    lc->length = 0; // default
    lc->record_count = 0; // default
    lc->created_at = time(NULL);

    return lc;
}

void log_chunk_destroy(LogChunk* lc) {
    if (!lc) return;

    if (lc->data) free(lc->data);
    free(lc);
}

int log_chunk_append(LogChunk* lc, const char* record, size_t record_len) {
    // Return 0 on success.
    // Return 1 if the chunk is full (not enough space left).
    // Return -1 on error (invalid pointers).
    if (!lc || !lc->data || !record || record_len == 0) return -1; // validate arguments

    // check remaining capacity
    size_t space_left = lc->capacity - lc->length;

    if (record_len > space_left) return 1; // no space left in chunk, caller must flush first

    // copy the bytes into the buffer right after the existing data
    memcpy(lc->data + lc->length, record, record_len);

    // update byte counter
    lc->length += record_len;
    lc->record_count++; // increment record counter

    return 0;
}

void log_chunk_flush(LogChunk* lc) {
    if (!lc || lc->length == 0) return;

    // print on the console for now
    printf("--- [FLUSH CHUNK: %zu records, %zu bytes] ---\n", lc->record_count, lc->length);
    fwrite(lc->data, sizeof(char), lc->length, stdout);
    fflush(stdout);

    // reset the chunk state to reuse it
    lc->length = 0;
    lc->record_count = 0;
    lc->created_at = time(NULL);
}

FollowerContext* follower_init(void) {
    // allocate memory and handle error
    FollowerContext* ctx = calloc(1, sizeof(FollowerContext));
    if (!ctx) {
        perror("ctx allocation failed");
        return NULL;
    }

    ctx->inotify_fd = inotify_init1(IN_CLOEXEC);
    if (ctx->inotify_fd < 0) {
        perror("inotify_init1 failed");
        exit(EXIT_FAILURE);
    }

    ctx->checkpoint_fd = checkpoint_open(CHECKPOINT_DB_PATH);
    if (ctx->checkpoint_fd < 0) {
        exit(EXIT_FAILURE);
    }

    ctx->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (ctx->epoll_fd < 0) {
        perror("epoll_create1 failed");
        exit(EXIT_FAILURE);
    }

    // tell epoll to watch inotify_fd
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = ctx->inotify_fd;
    if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, ctx->inotify_fd, &ev) < 0) {
        perror("epoll ctl for inotify fd failed");
        exit(EXIT_FAILURE);
    }

    ctx->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (ctx->timer_fd < 0) {
        perror("timerfd_create failed");
        exit(EXIT_FAILURE);
    }

    // arming the timer (500 ms ticks)
    struct itimerspec ts;
    ts.it_interval.tv_sec = 0;
    ts.it_interval.tv_nsec = FLUSH_INTERVAL_MS * 1000 * 1000;
    ts.it_value.tv_sec = 0;
    ts.it_value.tv_nsec = FLUSH_INTERVAL_MS * 1000 * 1000;

    if (timerfd_settime(ctx->timer_fd, 0, &ts, NULL) < 0) {
        perror("timerfd_settime for timer_fd failed");
        exit(EXIT_FAILURE);
    }

    // register timer_fd with epoll
    ev.events = EPOLLIN;
    ev.data.fd = ctx->timer_fd;
    if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, ctx->timer_fd, &ev) < 0) {
        perror("epoll_ctl timer failed");
    }

    ctx->files_by_wd = hashmap_init(STARTING_CAPACITY);
    if (!ctx->files_by_wd) exit(EXIT_FAILURE);

    ctx->files_by_path = hashmap_init(STARTING_CAPACITY);
    if (!ctx->files_by_path) exit(EXIT_FAILURE);

    ctx->dirs_by_wd = hashmap_init(STARTING_CAPACITY);
    if (!ctx->dirs_by_wd) exit(EXIT_FAILURE);

    ctx->dirs_by_path = hashmap_init(STARTING_CAPACITY);
    if (!ctx->dirs_by_path) exit(EXIT_FAILURE);

    ctx->active_chunk = log_chunk_create(CHUNK_CAPACITY);
    if (!ctx->active_chunk) exit(EXIT_FAILURE);

    // initialize the queue
    chunk_queue_init(&ctx->queue);

    ctx->is_paused = false; // default

    return ctx;
}

void follower_destroy(FollowerContext* ctx) {
    if (!ctx) return;

    ctx->is_paused = false; // Disarm catch-up triggers during teardown
    // free the chunk
    if (ctx->active_chunk) {
        if (ctx->active_chunk->length > 0)
            follower_seal_active_chunk(ctx); // Seal any pending logs before exiting
        log_chunk_destroy(ctx->active_chunk);
        ctx->active_chunk = NULL;
    }

    follower_drain_queue(ctx, 0); // Drain all remaining chunks
    chunk_queue_destroy(&ctx->queue);

    // Clean up all tracked files
    for (size_t i = 0; i < ctx->files_by_path->capacity; i++) {
        HashNode* node = ctx->files_by_path->nodeList[i];
        while (node) {
            Trackedfile* f = (Trackedfile*)node->value;
            if (f->file_wd >= 0) inotify_rm_watch(ctx->inotify_fd, f->file_wd);
            tracked_file_destroy(f);
            node = node->next;
        }
    }

    // Clean up all tracked directories
    for (size_t i = 0; i < ctx->dirs_by_path->capacity; i++) {
        HashNode* node = ctx->dirs_by_path->nodeList[i];
        while (node) {
            TrackedDir* d = (TrackedDir*)node->value;
            if (d->dir_wd >= 0) inotify_rm_watch(ctx->inotify_fd, d->dir_wd);
            tracked_dir_destroy(d);
            node = node->next;
        }
    }

    // free the hashmaps
    hashmap_free(ctx->files_by_wd);
    hashmap_free(ctx->files_by_path);
    hashmap_free(ctx->dirs_by_wd);
    hashmap_free(ctx->dirs_by_path);

    // close the master inotify descriptor
    close(ctx->inotify_fd);

    // close the database file
    if (ctx->checkpoint_fd >= 0) {
        checkpoint_close(ctx->checkpoint_fd);
        ctx->checkpoint_fd = -1; // reset
    }

    // close the timer_fd
    if (ctx->timer_fd >= 0) {
        close(ctx->timer_fd);
        ctx->timer_fd = -1; // reset
    }

    // close the master epoll instance
    if (ctx->epoll_fd >= 0) {
        close(ctx->epoll_fd);
        ctx->epoll_fd = -1; //reset
    }

    free(ctx);
}

int follower_add_target(FollowerContext* ctx, const char* file_path) {
    int err; // checking for function errors
    // create the file
    Trackedfile* file = tracked_file_create(file_path);
    if (!file) return -1;

    // check if directory is already monitored
    TrackedDir* dir = (TrackedDir*)hashmap_get(ctx->dirs_by_path, file->dir_path);
    if (!dir) { // directory is not monitored
        dir = tracked_dir_create(file->dir_path); // create the directory
        if (!dir) { tracked_file_destroy(file); return -1; }

        // add directory watch
        dir->dir_wd = inotify_add_watch(ctx->inotify_fd, dir->dir_path, IN_CREATE | IN_MOVED_TO | IN_DELETE | IN_MOVED_FROM);
        if (dir->dir_wd < 0) { // handle error
            perror("Directory watch failed");
            tracked_dir_destroy(dir);
            tracked_file_destroy(file);
            return -1;
        }

        // store this in the hashmaps
        err = hashmap_set(ctx->dirs_by_path, dir->dir_path, (void*)dir);
        if (err == -1) {
            fprintf(stderr, "Hashmap set failed for directory %s\n", dir->dir_path);
            tracked_dir_destroy(dir);
            tracked_file_destroy(file);
            return -1;
        }

        char key[32];
        snprintf(key, sizeof(key), "dir:%d", dir->dir_wd);
        err = hashmap_set(ctx->dirs_by_wd, key, (void*)dir);
        if (err == -1) {
            fprintf(stderr, "Hashmap set failed for directory %s\n", dir->dir_path);
            tracked_dir_destroy(dir);
            tracked_file_destroy(file);
            return -1;
        }
    }

    // increment reference count of the directory
    dir->ref_count++;

    // register the file path
    err = hashmap_set(ctx->files_by_path, file->file_path, (void*)file);
    if (err == -1) {
        fprintf(stderr, "Hashmap set failed for file %s\n", file->file_path);
        tracked_file_destroy(file); // not destroying dir here as other files might be under it
        return -1;
    }

    // try to open the file
    struct stat st;
    file->fd = open(file->file_path, O_RDONLY | O_CLOEXEC);
    if (file->fd < 0) { // open call failure
        if (errno == ENOENT) {
            file->fd = -1;
            file->file_wd = -1;
            file->is_active = false;
        }
        else {
            perror("file open failed");
            return -1;
        }
    }

    if (file->fd >= 0) { // open call success
        err = fstat(file->fd, &st); // read metadata about the file
        if (err < 0) {
            perror("fstat failed");
            tracked_file_destroy(file); // dont destroy dir
            return -1;
        }

        // set inode, dev, is_active
        file->inode = st.st_ino;
        file->dev = st.st_dev;
        file->is_active = true;

        // query the checkpoint database first to see if the file was monitored before
        off_t saved_offset = 0;
        int found = checkpoint_find(ctx->checkpoint_fd, file->dev, file->inode, &saved_offset);

        if (found == 0) { // the file was tracked before
            // truncation check
            if (saved_offset <= st.st_size) {
                // resume from offset
                file->offset = saved_offset;
                lseek(file->fd, saved_offset, SEEK_SET);
            }
            else { // file was truncated while agent was offline
                // rewind to start
                file->offset = 0;
                lseek(file->fd, 0, SEEK_SET);
                checkpoint_save(ctx->checkpoint_fd, file->dev, file->inode, 0); // save to database
            }
        }
        else { // the file was not tracked before
            // start in tail mode
            file->offset = st.st_size;
            // seek to end
            lseek(file->fd, 0, SEEK_END);
            checkpoint_save(ctx->checkpoint_fd, file->dev, file->inode, file->offset); // save to database
        }

        // add file watch
        file->file_wd = inotify_add_watch(ctx->inotify_fd, file->file_path, IN_MODIFY | IN_ATTRIB);
        if (file->file_wd < 0) { // handle error
            perror("File watch failed");
            tracked_file_destroy(file); // dont destroy dir
            return -1;
        }

        // register the file wd
        char key[32];
        snprintf(key, sizeof(key), "wd:%d", file->file_wd);
        err = hashmap_set(ctx->files_by_wd, key, (void*)file);
        if (err == -1) {
            fprintf(stderr, "Hashmap set failed for file %s\n", file->file_path);
            tracked_file_destroy(file); // dont destroy dir
            return -1;
        }

        // catch-up ingestion
        if (found == 0 && file->offset < st.st_size) { // new logs were written to the file while the follower was offline
            // drain the logs
            drain_file(ctx, file);
        }
    }

    return 0;
}

void follower_seal_active_chunk(FollowerContext* ctx) {
    if (!ctx || !ctx->active_chunk || ctx->active_chunk->length == 0) return; // invalid arguments

    // push chunk to the queue
    int err = chunk_queue_push(&ctx->queue, ctx->active_chunk);
    if (err == -1) {
        fprintf(stderr, "Chunk queue is full\n");
        ctx->is_paused = true; // pause reading
        return;
    }

    // check for backpressure
    if (chunk_queue_is_full(&ctx->queue) && !ctx->is_paused) {
        ctx->is_paused = true;
        fprintf(stderr, "Backpressure detected. Pausing disk ingestion\n");
    }

    // allocate new active chunk and replace
    ctx->active_chunk = log_chunk_create(CHUNK_CAPACITY);
}

void follower_catchup_all(FollowerContext* ctx) {
    if (!ctx || !ctx->files_by_path) return; // invalid arguments

    // iterate through the files
    for (size_t i = 0; i < ctx->files_by_path->capacity; i++) {
        if (ctx->is_paused) break; // if catching up causes backpressure again, pause!!!

        HashNode* node = ctx->files_by_path->nodeList[i];
        while (node) {
            Trackedfile* f = (Trackedfile*)node->value;

            struct stat st;
            if (f && f->fd >= 0) {
                fstat(f->fd, &st);
                if (f->offset < st.st_size) {
                    drain_file(ctx, f);
                }
            }

            node = node->next;
        }
    }
}

size_t follower_drain_queue(FollowerContext* ctx, size_t max_chunks) {
    if (!ctx || ctx->queue.count == 0) return 0;

    // drain the queue
    size_t drained = 0;
    while (ctx->queue.count && (max_chunks == 0 || drained < max_chunks)) {
        LogChunk* chunk = chunk_queue_pop(&ctx->queue);
        if (!chunk) break;

        // simulate transmission (for now)
        printf("=== [CONSUMER TRANSMIT: %zu records, %zu bytes | Queue remaining: %zu] ===\n", chunk->record_count, chunk->length, ctx->queue.count);
        fwrite(chunk->data, sizeof(char), chunk->length, stdout);
        fflush(stdout);

        // destroy transmitted chunk
        log_chunk_destroy(chunk);
        drained++;
    }

    // release backpressure and trigger catch-up
    if (ctx->is_paused && ctx->queue.count <= QUEUE_LOW_WATERMARK) {
        ctx->is_paused = false;
        fprintf(stderr, "[BACKPRESSURE RELEASED] Queue dropped to %zu chunks (<= low watermark %d). Resuming disk ingestion.\n",
                ctx->queue.count, QUEUE_LOW_WATERMARK);
        follower_catchup_all(ctx);
    }

    return drained;
}
