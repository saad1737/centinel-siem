#include "log_follower.h"

static volatile sig_atomic_t keep_running = 1;

static void handle_sigint(int sig) {
    (void)sig;
    keep_running = 0;
}

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
        free(ctx);
        return NULL;
    }

    ctx->files_by_wd = hashmap_init(STARTING_CAPACITY);
    if (!ctx->files_by_wd) { close(ctx->inotify_fd); free(ctx); return NULL; }

    ctx->files_by_path = hashmap_init(STARTING_CAPACITY);
    if (!ctx->files_by_path) { free(ctx->files_by_wd); close(ctx->inotify_fd); free(ctx); return NULL; }

    ctx->dirs_by_wd = hashmap_init(STARTING_CAPACITY);
    if (!ctx->dirs_by_wd) { free(ctx->files_by_path); free(ctx->files_by_wd); close(ctx->inotify_fd); free(ctx); return NULL; }

    ctx->dirs_by_path = hashmap_init(STARTING_CAPACITY);
    if (!ctx->dirs_by_path) { free(ctx->dirs_by_wd); free(ctx->files_by_path); free(ctx->files_by_wd); close(ctx->inotify_fd); free(ctx); return NULL; };

    return ctx;
}

void follower_destroy(FollowerContext* ctx) {
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

        // set inode, dev, offset
        file->inode = st.st_ino;
        file->offset = st.st_size;
        file->dev = st.st_dev;
        file->is_active = true;

        // seek to end
        lseek(file->fd, 0, SEEK_END);

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
    }

    return 0;
}

void drain_file(Trackedfile* file) {
    char chunk[MAX_CHUNK_LEN]; // buffer to store the logs
    ssize_t bytes_read = read(file->fd, chunk, sizeof(chunk));
    ssize_t partial_idx = 0;
    ssize_t unconsumed = 0;
    bool found = false;

    while (bytes_read > 0) {
        // perform backwards scan to look for the last '\n'
        found = false;
        for (ssize_t i = bytes_read - 1; i >= 0; i--) {
            if (chunk[i] == '\n') { // last '\n' found
                found = true;
                partial_idx = i + 1;
                // print the complete log lines with a files name prefix for now
                printf("[%s] ", file->file_name);
                fwrite(chunk, sizeof(char), partial_idx, stdout);
                fflush(stdout);

                unconsumed = bytes_read - partial_idx;
                if (unconsumed > 0) {
                    lseek(file->fd, -unconsumed, SEEK_CUR); // backtrack seek to that point
                }

                // update file offset
                file->offset += partial_idx;
                break;
            }
        }

        if (!found) {
            if (bytes_read == sizeof(chunk)) { // buffer could not hold entire data that arrived
                // flush to stdout for now and resume reading
                printf("[%s] ", file->file_name);
                fwrite(chunk, sizeof(char), bytes_read, stdout);
                fflush(stdout);
                file->offset += bytes_read;
                // no break. We continue to read...
            }
            else {
                // read found no complete lines (no '\n' found)
                lseek(file->fd, -bytes_read, SEEK_CUR);
                break;
            }
        }

        bytes_read = read(file->fd, chunk, sizeof(chunk));
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
        exit(EXIT_FAILURE);
    }

    // add files to monitor one by one (testing)
    follower_add_target(ctx, "/tmp/test1.log");
    follower_add_target(ctx, "/tmp/test2.log");

    // declare an event buffer
    char event_buf[EVENT_BUF_LEN] __attribute__((aligned(__alignof__(struct inotify_event)))); // aligning packing is critical
    ssize_t num_read; // number of bytes read
    while (keep_running) {
        num_read = read(ctx->inotify_fd, event_buf, sizeof(event_buf)); // read the event
        if (num_read < 0) { // handle exit signal or error
            if (errno == EINTR) continue; // signal exit (SIGINT and SIGTERM)
            else {
                perror("event read failed");
                exit(EXIT_FAILURE);
            }
        }

        // handle all events collected by the read call
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
                        }
                    }
                    else {
                        perror("fstat failed during truncation check");
                    }
                    drain_file(file);
                }
                else if (event->mask & (IN_DELETE_SELF | IN_MOVE_SELF)) {
                    // File moved or unlinked
                    drain_file(file);
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
                                drain_file(target_file);
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

    // cleanup
    follower_destroy(ctx);
    printf("\nStopped monitoring.\n");
    return EXIT_SUCCESS;
}
