#ifndef HASHMAP_H
#define HASHMAP_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define STARTING_CAPACITY 1024

typedef struct HashNode{
    char* key;
    void* value;
    struct HashNode* next;
} HashNode;

typedef struct {
    HashNode** nodeList;
    size_t capacity;
    size_t size;
} HashMap;

HashMap* hashmap_init(size_t capacity); // returns NULL on failure
int hashmap_set(HashMap* hashmap, const char* key, void* value); // returns -1 on failure
void* hashmap_get(HashMap* hashmap, const char* key); // returns NULL on failure
void* hashmap_remove(HashMap* hashmap, const char* key); // returns NULL on failure
void hashmap_free(HashMap* hashmap);

#endif
