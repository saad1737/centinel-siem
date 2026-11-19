#ifndef CHUNK_QUEUE_H
#define CHUNK_QUEUE_H

#include <stddef.h>
#include <stdbool.h>

#define QUEUE_MAX_CHUNKS 64 // 64 chunks * 16 KB = ~1 MB maximum RAM limit
#define QUEUE_HIGH_WATERMARK 48 // 75% full -> Trigger backpressure (pause file reads)
#define QUEUE_LOW_WATERMARK 16 // 25% full -> Release backpressure (resume file reads)

// forward declaration
typedef struct LogChunk LogChunk;

typedef struct {
    LogChunk* entries[QUEUE_MAX_CHUNKS]; // Array of chunk pointers
    size_t head; // Index of the next chunk to dequeue (pop)
    size_t tail; // Index where the next chunk will be enqueued (push)
    size_t count; // Number of chunks currently waiting in the queue
    size_t capacity; // Maximum capacity (QUEUE_MAX_CHUNKS)
} ChunkQueue;

/* Initializes the queue structure */
void chunk_queue_init(ChunkQueue* q);

/* Pushes a sealed chunk into the queue.
 Returns 0 on success, or -1 if the queue is full */
int chunk_queue_push(ChunkQueue* q, LogChunk* chunk);

/* Pops the oldest chunk from the queue.
 Returns pointer to the chunk, or NULL if empty */
LogChunk* chunk_queue_pop(ChunkQueue* q);

/* Returns current number of queued chunks */
size_t chunk_queue_count(const ChunkQueue* q);

/* Checks if queue has hit the high watermark */
bool chunk_queue_is_full(const ChunkQueue* q);

/* Frees any remaining chunks inside the queue on shutdown */
void chunk_queue_destroy(ChunkQueue* q);

#endif
