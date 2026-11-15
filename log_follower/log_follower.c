#include "log_follower.h"
#include <asm-generic/errno-base.h>

static volatile sig_atomic_t keep_running = 1;

static void handle_sigint(int sig) {
    (void)sig;
    keep_running = 0;
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
                // print the complete log lines for now
                fwrite(chunk, sizeof(char), partial_idx, stdout);

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
                fwrite(chunk, sizeof(char), bytes_read, stdout);
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

    // initialize inotify
    int inotify_fd = inotify_init1(IN_CLOEXEC);
    if (inotify_fd < 0) {
        perror("inotify_init1");
        return EXIT_FAILURE;
    }

    // testing with a statically declared struct first. (to test /tmp/text.log)
    Trackedfile file;
    file.fd = -1;
    file.dir_wd = -1;
    file.file_wd = -1;
    file.offset = 0;
    snprintf(file.file_name, sizeof(file.file_name), "%s", "text.log");
    snprintf(file.file_path, sizeof(file.file_path), "%s", "/tmp/text.log");
    snprintf(file.dir_path, sizeof(file.dir_path), "%s", "/tmp");

    // initialize directory watch
    file.dir_wd = inotify_add_watch(inotify_fd, file.dir_path, IN_CREATE | IN_MOVED_TO | IN_DELETE | IN_MOVED_FROM);
    if (file.dir_wd < 0) {
        perror("inotify_add_watch for directory failed");
        exit(EXIT_FAILURE);
    }

    // open the file and start following from the end
    file.fd = open(file.file_path, O_RDONLY | O_CLOEXEC);
    if (file.fd < 0) {
        if (errno == ENOENT) { // file does not exist yet
            file.fd = -1;
            file.file_wd = -1;
        }
        else { // actual file opening error
            perror("open call failed");
            exit(EXIT_FAILURE);
        }
    }

    // extracting information of the file
    struct stat fileStat;
    int err;

    if (file.fd >= 0) { // file was successfully opened
        err = fstat(file.fd, &fileStat);
        if (err < 0) {
            perror("fstat failed");
            exit(EXIT_FAILURE);
        }

        file.inode = fileStat.st_ino; // storing the inode number
        file.offset = fileStat.st_size; // storing the size of the file

        lseek(file.fd, 0, SEEK_END); // seek to the end of the file (tail mode)

        // initialize file watch
        file.file_wd = inotify_add_watch(inotify_fd, file.file_path, IN_MODIFY | IN_ATTRIB);
        if (file.file_wd < 0) {
            perror("inotify_add_watch for file failed");
            exit(EXIT_FAILURE);
        }
    }

    // declare an event buffer
    char event_buf[EVENT_BUF_LEN] __attribute__((aligned(__alignof__(struct inotify_event)))); // aligning packing is critical
    ssize_t num_read; // number of bytes read
    while (keep_running) {
        num_read = read(inotify_fd, event_buf, sizeof(event_buf)); // read the event
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

            // Branch A - handle target file event
            if (event->wd == file.file_wd) {
                if (event->mask & IN_MODIFY) { // truncation check
                    err = fstat(file.fd, &fileStat); // calling to check the file size
                    if (err < 0) {
                        perror("fstat failed");
                        exit(EXIT_FAILURE);
                    }

                    if (fileStat.st_size < file.offset) { // file got truncated
                        file.offset = 0; // reset
                        lseek(file.fd, 0, SEEK_SET); // seek the starting of the file
                    }

                    // call the drain helper here
                    drain_file(&file);
                }
                else if (event->mask & (IN_DELETE_SELF | IN_MOVE_SELF)) { // file deleted or moved (renamed)
                    // file watch is dead
                    inotify_rm_watch(inotify_fd, file.file_wd); // remove watch
                    file.file_wd = -1; // reset;

                    // call the drain helper here
                    drain_file(&file);

                    close(file.fd);
                    file.fd = -1; // reset
                }
            }
            // Branch B - handle directory event for the specific tracked file
            else if (event->len > 0 && !strcmp(event->name, file.file_name)) {
                if (event->wd == file.dir_wd) {
                    if (event->mask & (IN_CREATE | IN_MOVED_TO)) { // file just appeared
                        // clean up old watch just in case
                        if (file.file_wd >= 0) { inotify_rm_watch(inotify_fd, file.file_wd); file.file_wd = -1; }
                        if (file.fd >= 0) { close(file.fd); file.fd = -1; }

                        // open the newly created file
                        file.fd = open(file.file_path, O_RDONLY | O_CLOEXEC);
                        if (file.fd < 0) {
                            perror("open call failed");
                            exit(EXIT_FAILURE);
                        }

                        // add file watch
                        file.file_wd = inotify_add_watch(inotify_fd, file.file_path, IN_MODIFY | IN_ATTRIB);
                        if (file.file_wd < 0) {
                            perror("inotify_add_watch for file failed");
                            exit(EXIT_FAILURE);
                        }

                        file.offset = 0; // reset offset
                        lseek(file.fd, 0, SEEK_SET); // new file, seek from beginning

                        // fetch new inode and store
                        err = fstat(file.fd, &fileStat); // calling to check the file size
                        if (err < 0) {
                            perror("fstat failed");
                            exit(EXIT_FAILURE);
                        }
                        file.inode = fileStat.st_ino;

                        // call drain to read the initial contents
                        drain_file(&file);
                    }
                    else if (event->mask & (IN_DELETE | IN_MOVED_FROM)) { // the file was removed from the directory
                        // clean up
                        if (file.file_wd >= 0) { inotify_rm_watch(inotify_fd, file.file_wd); file.file_wd = -1; }
                        if (file.fd >= 0) { close(file.fd); file.fd = -1; }
                    }
                }
            }
            ptr += sizeof(struct inotify_event) + event->len; // next event
        }
    }

    // cleanup
    if (file.dir_wd >= 0) inotify_rm_watch(inotify_fd, file.dir_wd);
    if (file.file_wd >= 0) inotify_rm_watch(inotify_fd, file.file_wd);
    if (inotify_fd >= 0) close(inotify_fd);
    if (file.fd >= 0) close(file.fd);

    printf("\nStopped monitoring.\n");
    return EXIT_SUCCESS;
}
