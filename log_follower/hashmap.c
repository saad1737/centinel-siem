#include "hashmap.h"

static const uint64_t magic_prime = 5381;

static uint64_t djb_hash(HashMap* hashmap, const char* string) { // A hash function following the djb algorithm
    uint64_t val = magic_prime;
    for (size_t i = 0; string[i] != '\0'; i++) {
        val = (val * 33) + string[i];
        val %= hashmap->capacity;
    }

    val %= hashmap->capacity;
    return val;
}

HashMap* hashmap_init(size_t capacity) {
    HashMap* hashmap = malloc(sizeof(HashMap));
    if (!hashmap) {
        fprintf(stderr, "Failed to allocate memory for initializing Hashmap\n");
        return NULL;
    }

    hashmap->capacity = capacity;
    hashmap->size = 0;
    hashmap->nodeList = calloc(capacity, sizeof(HashNode*));
    if (!hashmap->nodeList) {
        fprintf(stderr, "Failed to allocate memory for the Hashmap nodes\n");
        free(hashmap);
        return NULL;
    }

    return hashmap;
}

int hashmap_set(HashMap* hashmap, const char* key, void* value) {
    uint64_t idx = djb_hash(hashmap, key);

    HashNode* temp = hashmap->nodeList[idx]; // O(1) complexity
    while (temp) {
        if (!strcmp(temp->key, key)) {
            temp->value = value;
            return 0;
        }
        temp = temp->next;
    }

    HashNode* newNode = malloc(sizeof(HashNode));
    if (!newNode) {
        fprintf(stderr, "Failed to allocate memory for a hashnode\n");
        return -1;
    }

    newNode->key = strdup(key);
    if (!newNode->key) {
        fprintf(stderr, "Failed to allocate memory for the key\n");
        return -1;
    }
    newNode->value = value;

    // insert at head . O(1) complexity
    newNode->next = hashmap->nodeList[idx];
    hashmap->nodeList[idx] = newNode;
    hashmap->size++;

    return 0;
}

void* hashmap_get(HashMap* hashmap, const char* key) {
    uint64_t idx = djb_hash(hashmap, key);

    HashNode* temp = hashmap->nodeList[idx]; // O(1) complexity
    while (temp) {
        if (!strcmp(temp->key, key)) return temp->value;
        temp = temp->next;
    }

    return NULL;
}

void* hashmap_remove(HashMap* hashmap, const char* key) {
    uint64_t idx = djb_hash(hashmap, key);

    HashNode* temp = hashmap->nodeList[idx]; // O(1) complexity
    if (!temp) return NULL;

    // delete head
    if (!strcmp(temp->key, key)) {
        hashmap->nodeList[idx] = hashmap->nodeList[idx]->next;
        void* val = temp->value;
        free(temp->key);
        free(temp);
        hashmap->size--;
        return val;
    }

    while (temp->next) {
        if (!strcmp(temp->next->key, key)) {
            HashNode* toDelete = temp->next;
            temp->next = temp->next->next;
            void* val = toDelete->value;
            free(toDelete->key);
            free(toDelete);
            hashmap->size--;
            return val;
        }

        temp = temp->next;
    }

    printf("No item of key: %s found to remove\n", key);
    return NULL;
}

void hashmap_free(HashMap* hashmap) {
    for (size_t i = 0; i < hashmap->capacity; i++) {
        HashNode* temp = hashmap->nodeList[i];
        while (temp) {
            HashNode* toDelete = temp;
            temp = temp->next;
            free(toDelete->key);
            free(toDelete);
        }
    }

    free(hashmap->nodeList);
    free(hashmap);
}
