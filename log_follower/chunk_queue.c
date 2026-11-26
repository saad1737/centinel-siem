#include "chunk_queue.h"
#include "log_follower.h"

void chunk_queue_init(ChunkQueue* q) { // resets the whole queue
    q->head = 0;
    q->tail = 0;
    q->count = 0;
    q->capacity = QUEUE_MAX_CHUNKS;
    memset(q->entries, 0, sizeof(q->entries));
}

int chunk_queue_push(ChunkQueue* q, LogChunk* chunk) {
    if (!q || !chunk) return -1; // arguments invalid

    if (q->count >= q->capacity) return -1; // queue is full

    q->entries[q->tail] = chunk; // pushing the chunk at tail

    q->tail = (q->tail + 1) % q->capacity; // circular advancement of the tail (ring buffer)

    q->count++; // increment count

    return 0;
}

LogChunk* chunk_queue_pop(ChunkQueue* q) {
    if (!q || q->count == 0)  return NULL; // queue does not exist or queue is empty

    // grab the chunk at the head
    LogChunk* lc = q->entries[q->head];
    q->entries[q->head] = NULL; // popped
    q->head = (q->head + 1) % q->capacity; // circular advancement of the head (ring buffer)

    q->count--; // decrement count

    return lc;
}

size_t chunk_queue_count(const ChunkQueue* q) {
    return q->count;
}

bool chunk_queue_is_full(const ChunkQueue* q) {
    return q->count >= QUEUE_HIGH_WATERMARK;
}

LogChunk* chunk_queue_peek(const ChunkQueue* q) {
    if (!q || q->count == 0) return NULL;
    return q->entries[q->head];
}

void chunk_queue_destroy(ChunkQueue* q) {
    if (!q) return;

    // destroy all the chunks in this queue
    while (q->count) {
        LogChunk* lc = chunk_queue_pop(q);
        log_chunk_destroy(lc);
    }
}
