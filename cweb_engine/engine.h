#ifndef ENGINE_H
#define ENGINE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <getopt.h>
#include <unistd.h>
#include <cweb.h>

#define ENGINE_DEFAULT_PORT 8765
#define MAX_BATCH_CAPACITY 4096 // a batch can only have maximum of 4096 logs
#define DEFAULT_BATCH_THRESHOLD 2048

typedef struct {
    int port;
    size_t batch_threshold;
} EngineConfig;

#endif