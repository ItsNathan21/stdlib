#include "malloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>

#define PAGE_SIZE (4096)
#define ALLOC_BIT (1 << 0)
#define PREV_ALLOC_BIT (1 << 1)
#define PAGE_SIZE (4096)

#define GET_ALLOC(x) ((x & ALLOC_BIT) >> 0)
#define GET_PREV_ALLOC(x) ((x & PREV_ALLOC_BIT) >> 1)
#define GET_SIZE(x) (x & ~(ALLOC_BIT | PREV_ALLOC_BIT))

#define MIN_BLOCK_SIZE (24)

struct block {
    uint64_t header;
    struct block *prev_block;
    struct block *next_block;
};

typedef struct block block_t;

typedef struct {
    block_t *start;
    block_t *end;
} heap_t;

heap_t heap = {.start = NULL, .end = NULL};
block_t *free_list = NULL;

extern void *sbrk(intptr_t inc);
void check_heap(void);
void print_heap(void);
void print_free_list(void);

uint64_t round_to_multiple(uint64_t size, uint64_t multiple) {
    return multiple * ((size + (multiple - 1)) / multiple);
}

uint64_t *get_footer(block_t *block) {
    return (uint64_t *)((uint8_t *)block + GET_SIZE(block->header) + sizeof(block_t) - 8);
}

void write_footer(block_t *block) {
    uint64_t *address = (uint64_t *)((uint8_t *)block + GET_SIZE(block->header) + sizeof(block_t) - 8);
    *address = GET_SIZE(block->header);
}

void write_to_block(block_t *block, uint64_t size, uint64_t allocated, uint64_t prev_allocated) {
    block->header = GET_SIZE(size) | (allocated << 0) | (prev_allocated << 1);
    if (!allocated) write_footer(block);
}

void *block_to_payload(block_t *block) {
    return (void *)(&block->prev_block);
}

block_t *payload_to_header(void *ptr) {
    return (block_t *)((char *)ptr - 8);
}

block_t *get_prev_block(block_t *block) {
    uint64_t *footer_ptr = (uint64_t *)((uint8_t *)block - 8);

    uint64_t size_of_prev = *footer_ptr;

    return (block_t *)((uint8_t *)block - size_of_prev - sizeof(block_t));
}

block_t *get_next_block(block_t *block) {
    if (block == heap.end) return NULL;
    return (block_t *)((uint8_t *)block + GET_SIZE(block->header) + sizeof(block_t));
}

void remove_from_free(block_t *block) {
    if (block->prev_block != NULL) {
        block->prev_block->next_block = block->next_block;
    }
    else {
        free_list = block->next_block;
        if (free_list != NULL) free_list->prev_block = NULL;
    }
    if (block->next_block != NULL) {
        block->next_block->prev_block = block->prev_block;
    }
}

void add_to_free(block_t *block) {
    if (free_list == NULL) {
        free_list = block;
        block->next_block = NULL;
        block->prev_block = NULL;
        return;
    }
    block_t *current_head = free_list;
    block->next_block = current_head;
    block->prev_block = NULL;
    current_head->prev_block = block;
    free_list = block;
}

block_t *find_fit(uint64_t size) {
    for (block_t *block = free_list; block != NULL; block = block->next_block) {
        if (GET_SIZE(block->header) >= size && !GET_ALLOC(block->header)) {
            return block;
        }
    }
    return NULL;
}

/**
 * @brief FUCK FUCK FUCK FUCK FUCK FUCK 
 */
void coalesce(block_t *block) {
    uint64_t new_size = GET_SIZE(block->header);
    block_t *block_to_coalesce = block;
    if (!GET_PREV_ALLOC(block->header)) {
        block_t *prev_block = get_prev_block(block);
        block_to_coalesce = prev_block;
        new_size += GET_SIZE(prev_block->header) + sizeof(block_t);
        remove_from_free(prev_block);
    }
    block_t *next_block = get_next_block(block);
    if (!GET_ALLOC(next_block->header)) {
        new_size += GET_SIZE(next_block->header) + sizeof(block_t);
        remove_from_free(next_block);
    }
    write_to_block(block_to_coalesce, new_size, 0UL, GET_PREV_ALLOC(block_to_coalesce->header));
    add_to_free(block_to_coalesce);
}


void extend_heap(uint64_t size) {
    if (size < PAGE_SIZE) size = PAGE_SIZE;
    block_t *old_end = heap.end;
    if (sbrk((intptr_t)size) == (void *)-1) {
        fprintf(stderr, "sbrk() failed\n");
        exit(1);
    }
    uint64_t usable_size = size - sizeof(block_t);
    write_to_block(old_end, usable_size, 0UL, GET_PREV_ALLOC(old_end->header));
    heap.end = (block_t *)((uint8_t *)old_end + size);
    write_to_block(heap.end, 0UL, 1UL, 0UL);
    
    coalesce(old_end);
}


void initialize_heap(void) {
    block_t *start = (block_t *)sbrk(sizeof(block_t) * 2);
    if (start == NULL) {
        fprintf(stderr, "sbrk() failed on initialization call\n");
        exit(1);
    }
    heap.start = &start[0];
    heap.end = &start[1];
    heap.end->next_block = NULL;
    write_to_block(heap.start, 0UL, 1UL, 0UL);
    write_to_block(heap.end, 0UL, 1UL, 1UL);
    extend_heap(PAGE_SIZE);
}

void split_block(block_t *block, uint64_t size) {

    remove_from_free(block);
    block_t *next_block = get_next_block(block);

    if ((GET_SIZE(block->header) - size) < MIN_BLOCK_SIZE) {
        write_to_block(block, GET_SIZE(block->header), 1UL, GET_PREV_ALLOC(block->header));
        write_to_block(next_block, GET_SIZE(next_block->header), GET_ALLOC(next_block->header), 1UL);
        return;
    }

    uint64_t original_size = GET_SIZE(block->header);
    write_to_block(block, size, 1UL, GET_PREV_ALLOC(block->header));
    block_t *new_next = get_next_block(block);
    write_to_block(new_next, original_size - size - sizeof(block_t), 0UL, 1UL);
    coalesce(new_next);
}

void *mmalloc(uint64_t size) {
    if (size <= 0) return NULL;

    if (heap.start == NULL) initialize_heap();

    if (size < MIN_BLOCK_SIZE) size = round_to_multiple(size, MIN_BLOCK_SIZE);

    size = round_to_multiple(size, 2 * sizeof(uint64_t));

    block_t *ret;
    while ((ret = find_fit(size)) == NULL) extend_heap(PAGE_SIZE);

    split_block(ret, size);

    return block_to_payload(ret);
}

void mfree(void *ptr) {
    if (ptr == NULL) return;
    block_t *block = payload_to_header(ptr);
    write_to_block(block, GET_SIZE(block->header), 0UL, GET_PREV_ALLOC(block->header));

    block_t *next_block = get_next_block(block);
    write_to_block(next_block, GET_SIZE(next_block->header), GET_ALLOC(next_block->header), 0UL);

    coalesce(block);
}

void *mcalloc(uint64_t num_elements, uint64_t size) {
    size = size * num_elements;
    if (size < MIN_BLOCK_SIZE) size = round_to_multiple(size, MIN_BLOCK_SIZE);
    size = round_to_multiple(size, 2 * sizeof(uint64_t));
    void *ret_ptr = mmalloc(size);
    if (ret_ptr == NULL) return NULL;
    memset(ret_ptr, 0, size);
    return ret_ptr;
}

void *mrealloc(void *ptr, uint64_t size) {
    if (size == 0UL) {
        mfree(ptr);
        return NULL;
    }

    if (ptr == NULL) return mmalloc(size);

    uint64_t old_size = GET_SIZE(payload_to_header(ptr)->header);

    if (size < old_size) size = old_size;

    void *ret = mmalloc(size);

    memcpy(ret, ptr, old_size);

    mfree(ptr);

    return ret;
}

uint8_t allocs_are_correct(block_t *block) {
    if (GET_PREV_ALLOC(block->header) != GET_ALLOC(block->prev_block->header)) return 0;
    return 1;
}

void check_heap(void) {
    for (block_t *block = heap.start->next_block; block != heap.end; block = get_next_block(block)) {
        if (!allocs_are_correct(block)) perror("FAILED: Checkheap returns bad allocs\n");
    }
}

void print_heap(void) {
    printf("********************** PRINTING HEAP ***********************\n");
    for (block_t *block = heap.start; block != NULL; block = get_next_block(block)) {
        printf("-----------------------------------------------------------\n");
        printf("Block address is %.16lx\n", (uint64_t)block);
        if (!GET_ALLOC(block->header)) {
            printf("Block prev address is %.16lx\n", (uint64_t)block->prev_block);
            printf("Block next address is %.16lx\n", (uint64_t)block->next_block);
            printf("Block footer has size value %ld\n", GET_SIZE(*get_footer(block)));
        }
        printf("size is %ld bytes\n", GET_SIZE(block->header));
        printf("prev_alloc is %ld, this block alloc is %ld\n", GET_PREV_ALLOC(block->header), GET_ALLOC(block->header));
        printf("-----------------------------------------------------------\n");
    }
    printf("**********************               ***********************\n");
}

void print_free_list(void) {
    printf("################## PRINTING FREE LIST ###########################\n");
    for (block_t *block = free_list; block != NULL; block = block->next_block) {
        printf("Block address is 0x%.16lx\n", (uint64_t)block);
        printf("Block next ptr is 0x%.16lx\n", (uint64_t)block->next_block);
        printf("Block prev ptr is 0x%.16lx\n", (uint64_t)block->prev_block);
        printf("Block size is %ld\n", GET_SIZE(block->header));
    }
    printf("################## ################### ###########################\n");
}