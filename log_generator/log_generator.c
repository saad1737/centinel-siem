#include "log_generator.h"
#include <errno.h>
#include <signal.h>
#include <time.h>

// declare the global config struct here
static GeneratorConfig config;

// set by Ctrl+C / kill so the generator can flush and exit cleanly
static volatile sig_atomic_t stop_requested = 0;
static void handle_stop(int sig) { (void)sig; stop_requested = 1; }

static uint64_t ns_between(const struct timespec* a, const struct timespec* b) {
    int64_t elapsed = (int64_t)(b->tv_sec - a->tv_sec) * 1000000000LL
                    + b->tv_nsec - a->tv_nsec;
    return elapsed > 0 ? (uint64_t)elapsed : 0;
}

static struct timespec ts_add_ns(struct timespec t, uint64_t ns) {
    t.tv_sec += (time_t)(ns / 1000000000ULL);
    t.tv_nsec += (long)(ns % 1000000000ULL);
    if (t.tv_nsec >= 1000000000L) { t.tv_sec++; t.tv_nsec -= 1000000000L; }
    return t;
}

static int ts_compare(const struct timespec* a, const struct timespec* b) {
    if (a->tv_sec != b->tv_sec) return a->tv_sec < b->tv_sec ? -1 : 1;
    return (a->tv_nsec > b->tv_nsec) - (a->tv_nsec < b->tv_nsec);
}

// sleeps until an absolute CLOCK_MONOTONIC time, wakes up early when Ctrl+C arrives
static int sleep_until(const struct timespec* deadline) {
    int err;
    do {
        err = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, deadline, NULL);
    } while (err == EINTR && !stop_requested);
    if (err != 0 && err != EINTR) {
        errno = err;
        perror("clock_nanosleep");
        return -1;
    }
    return 0;
}

// Writes one "write window": it ends after total_logs lines or write_sec seconds
// (whichever comes first; 0 means no limit). Lines go to the file and the terminal.
static int write_window(FILE* output, const struct timespec* run_start, uint64_t* written) {
    char event[1024];
    struct timespec wstart, now;
    uint32_t batch_count = 0;
    uint64_t i = 0;

    // pacing: log number i is due at wstart + i * window / count (exact, works for fractions like 10 logs in 20 s)
    int fixed = config.total_logs && config.write_sec;
    uint64_t pace_count  = fixed ? config.total_logs : config.target_eps;
    uint64_t pace_window = fixed ? (uint64_t)config.write_sec * 1000000000ULL : 1000000000ULL;

    if (clock_gettime(CLOCK_MONOTONIC, &wstart) != 0) { perror("clock_gettime"); return -1; }

    while (!stop_requested) {
        if (config.total_logs && i >= config.total_logs) break;

        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) { perror("clock_gettime"); return -1; }
        if (config.write_sec && ns_between(&wstart, &now) >= (uint64_t)config.write_sec * 1000000000ULL) break;
        if (config.pause_sec && config.duration_sec &&
            ns_between(run_start, &now) >= (uint64_t)config.duration_sec * 1000000000ULL) {
            stop_requested = 1;   // total run time of pause mode is over
            break;
        }

        size_t len = gen_event(event, sizeof(event), &config);
        if (len == 0) {
            fprintf(stderr, "Failed to generate a log event\n");
            return -1;
        }
        if (fwrite(event, 1, len, output) != len) {
            perror("Writing log event");
            return -1;
        }
        if (config.verbosity && fwrite(event, 1, len, stdout) != len) {
            perror("Writing log event to stdout");
            return -1;
        }
        i++;
        (*written)++;

        int more = !(config.total_logs && i >= config.total_logs);
        uint64_t gap_ns = pace_window / pace_count;

        // flush every batch, and always when the gap is long (slow rates must show up at once)
        if (++batch_count >= config.batch_size || (config.mode != MODE_BENCHMARK && gap_ns >= 20000000ULL)) {
            if (fflush(output) != 0) { perror("Flushing log file"); return -1; }
            if (config.verbosity) fflush(stdout);
            batch_count = 0;
        }

        if (config.mode != MODE_BENCHMARK && (more || config.write_sec)) {
            // next slot (or the end of the window after the last log)
            unsigned __int128 off = (unsigned __int128)i * pace_window / pace_count;
            struct timespec due = ts_add_ns(wstart, (uint64_t)off);
            bool end_after_sleep = false;
            if (config.pause_sec && config.duration_sec) {
                struct timespec run_end = ts_add_ns(
                    *run_start, (uint64_t)config.duration_sec * 1000000000ULL);
                if (ts_compare(&due, &run_end) >= 0) {
                    due = run_end;
                    end_after_sleep = true;
                }
            }
            if (sleep_until(&due) != 0) return -1;
            if (end_after_sleep) stop_requested = 1;
        }
    }

    if (fflush(output) != 0) { perror("Flushing log file"); return -1; }
    if (config.verbosity) fflush(stdout);
    return 0;
}

static int generate_events(FILE* output) {
    struct timespec run_start;
    uint64_t written = 0;

    if (clock_gettime(CLOCK_MONOTONIC, &run_start) != 0) {
        perror("clock_gettime");
        return -1;
    }
    events_init(&config);

    for (uint64_t cycle = 1; !stop_requested; cycle++) {
        if (config.pause_sec) {
            printf("--- write window %llu ---\n", (unsigned long long)cycle);
            fflush(stdout);
        }
        if (write_window(output, &run_start, &written) != 0) return -1;

        // normal mode: one window only
        if (!config.pause_sec || stop_requested) break;

        // pause mode: sleep, then start the next window
        struct timespec now, wake;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
            perror("clock_gettime");
            return -1;
        }
        if (config.duration_sec &&
            ns_between(&run_start, &now) >= (uint64_t)config.duration_sec * 1000000000ULL) {
            break;
        }
        printf("--- paused for %u s ---\n", config.pause_sec);
        fflush(stdout);
        wake = ts_add_ns(now, (uint64_t)config.pause_sec * 1000000000ULL);
        if (config.duration_sec) {
            struct timespec run_end = ts_add_ns(
                run_start, (uint64_t)config.duration_sec * 1000000000ULL);
            if (ts_compare(&wake, &run_end) >= 0) {
                wake = run_end;
            }
        }
        if (sleep_until(&wake) != 0) return -1;
        if (config.duration_sec &&
            ns_between(&run_start, &wake) >= (uint64_t)config.duration_sec * 1000000000ULL) {
            break;
        }
    }

    struct timespec end;
    if (clock_gettime(CLOCK_MONOTONIC, &end) != 0) {
        perror("clock_gettime");
        return -1;
    }
    printf("Done: %llu logs written to %s in %.2f s\n", (unsigned long long)written,
           config.target_path, (double)ns_between(&run_start, &end) / 1e9);
    return 0;
}

int main(int argc, char** argv) {
    // fill the config with default values
    config_default_init(&config);

    // parse command line and update the config accordingly
    int parse_result = config_parse_cli(&config, argc, argv);
    if (parse_result < 0) {
        fprintf(stderr, "Parsing error\n");
        return EXIT_FAILURE;
    }
    if (parse_result > 0) return EXIT_SUCCESS;

    // validate the parsed values
    if (config_validate(&config) == -1) {
        fprintf(stderr, "Validation error\n");
        return EXIT_FAILURE;
    }

    // print summary
    config_dump(&config);

    // Ctrl+C / SIGTERM: stop the loop, flush the file, print the summary
    struct sigaction sa = {0};
    sa.sa_handler = handle_stop;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) != 0 || sigaction(SIGTERM, &sa, NULL) != 0) {
        perror("sigaction");
        return EXIT_FAILURE;
    }

    FILE* output = fopen(config.target_path, "a");
    if (!output) {
        perror(config.target_path);
        return EXIT_FAILURE;
    }

    int result = generate_events(output);
    events_free();
    if (fclose(output) != 0) {
        perror("Closing log file");
        result = -1;
    }

    return result == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}