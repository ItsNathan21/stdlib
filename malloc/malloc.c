#include "malloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

#define PAGE_SIZE (4096)
#define ALLOC_BIT (1 << 0)
#define ALLOC_BIT_POS (ALLOC_BIT - 1)
#define PREV_ALLOC_BIT (1 << 1)
#define PREV_ALLOC_BIT_POS (PREV_ALLOC_BIT - 1)
#define PAGE_SIZE (4096)
#define ALLOCATED (1)
#define FREE (0)
#define PREV_ALLOCATED (1)
#define PREV_FREE (0)
#define GET_ALLOC(x) ((x & ALLOC_BIT) >> ALLOC_BIT_POS)
#define GET_PREV_ALLOC(x) ((x & PREV_ALLOC_BIT) >> PREV_ALLOC_BIT_POS)
#define GET_SIZE(x) (x & ~(ALLOC_BIT | PREV_ALLOC_BIT))
#define MIN_BLOCK_SIZE (32)
#define BUCKETS (64)

#define UNUSED __attribute__((unused))

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

block_t *free_list[BUCKETS] = {NULL};

extern void *sbrk(intptr_t inc);
int check_heap(void);
void print_heap(void);
void print_free(void);
void dbg_printf(const char *fmt, ...);

#ifdef DEBUG
#define dbg_assert(cond) assert(cond)
#else
#define dbg_assert(cond) assert(1)
#endif

uint64_t round_to_multiple(uint64_t size, uint64_t multiple) {
    return multiple * ((size + (multiple - 1)) / multiple);
}

block_t *payload_to_header(void *payload) {
    return (block_t*)((uint8_t *)payload - sizeof(uint64_t));
}

void *header_to_payload(block_t *block) {
    return (void *)&block->prev_block;
}

block_t *prev_block(block_t *block) {
    uint64_t prev_size = GET_SIZE(*(uint64_t *)((char *)block - sizeof(uint64_t)));
    return (block_t *)((uint8_t *)block - prev_size);
}

uint64_t *get_footer(block_t *block) {
    return (uint64_t *)((uint8_t *)block + GET_SIZE(block->header) - sizeof(uint64_t));
}

void write_footer(block_t *block) {
    *get_footer(block) = block->header;
}

void write_to_block(block_t *block, uint64_t size, uint64_t allocated, uint64_t prev_allocated) {
    block->header = GET_SIZE(size) | (allocated << ALLOC_BIT_POS) | (prev_allocated << PREV_ALLOC_BIT_POS);
    if (allocated == FREE) write_footer(block);
}

block_t *next_block(block_t *block) {
    if (block == heap.end) return NULL;
    return (block_t *)((uint8_t *)block + GET_SIZE(block->header));
}

uint64_t get_free_index(uint64_t size) {
    if (size <= (1UL << 5)) return 0;
    int index = 63 - __builtin_clzl(size);
    return (index <= 5) ? 0 : (uint64_t)(index - 5);
}

void add_to_free(block_t *block) {
    dbg_assert(check_heap());

    uint64_t index = get_free_index(GET_SIZE(block->header));

    block->next_block = free_list[index];
    block->prev_block = NULL;
    if (free_list[index] != NULL)
        free_list[index]->prev_block = block;

    free_list[index] = block;

    dbg_assert(check_heap());
}

void remove_from_free(block_t *block) {
    if (block->prev_block != NULL) 
        block->prev_block->next_block = block->next_block;
    else {   
        free_list[get_free_index(GET_SIZE(block->header))] = block->next_block;
    }
    if (block->next_block != NULL) 
        block->next_block->prev_block = block->prev_block;
}

void coalesce(block_t *block) {

    block_t *next = next_block(block);
    block_t *coalescing = block;
    uint64_t size = GET_SIZE(block->header);

    if (!GET_PREV_ALLOC(block->header)) {
        block_t *prev = prev_block(block);
        coalescing = prev;
        size += GET_SIZE(prev->header);
        remove_from_free(prev);
    }
    if (next != NULL && !GET_ALLOC(next->header)) {
        size += GET_SIZE(next->header);
        remove_from_free(next);
    }
    write_to_block(coalescing, size, FREE, GET_PREV_ALLOC(coalescing->header));
    add_to_free(coalescing);
}

void extend_heap(uint64_t size) {
    dbg_assert(check_heap());

    if (sbrk(size + sizeof(block_t)) == (void *)-1) {
        fprintf(stderr, "sbrk() failed on extending the heap with size %ld\n", size);
        exit(1);
    }
    block_t *new_block = heap.end;
    heap.end = (block_t *)((uint8_t *)heap.end + size + sizeof(block_t));
    write_to_block(new_block, size + sizeof(block_t), FREE, GET_PREV_ALLOC(new_block->header));
    write_to_block(heap.end, sizeof(block_t), ALLOCATED, PREV_FREE);
    coalesce(new_block);

    dbg_assert(check_heap());
}

/**
 * @brief Initializes the heap, this is a bunch of syscalls that don't mean a whole lot. 
 * The only important part is the sbrk() call, which extends the current heap break
 */
void initialize_heap(void) {
    block_t *start = sbrk(2 * sizeof(block_t));
    if (start == (void *)-1) {
        fprintf(stderr, "sbrk() failed on initialization call\n");
        exit(1);
    }
    heap.start = start;
    heap.end = start + 1;
    write_to_block(heap.end, sizeof(block_t), ALLOCATED, PREV_ALLOCATED);
    write_to_block(heap.start, sizeof(block_t), ALLOCATED, PREV_FREE);
    extend_heap(PAGE_SIZE);

    dbg_assert(check_heap());
}

/**
 * @brief Searches through the heap and looks for the first suitable
 * block that will work, given the size
 */
block_t *find_fit(uint64_t size) {
    for (uint64_t idx = get_free_index(size); idx < 64; idx++) {
        for (block_t *block = free_list[idx]; block != NULL; block = block->next_block) {
            if (!GET_ALLOC(block->header) && (GET_SIZE(block->header) >= size)) {
                return block;
            }
        }
    }
    return NULL;
}

/**
 * @brief Given a block that will be allocated, we need to split
 * this block if its far too small for the block we've given it. 
 * We should mark the part we need as allocated, but then the rest as free. 
 */
void split_block(block_t *block, uint64_t size) {
    dbg_assert(GET_ALLOC(block->header) == FREE);
    dbg_assert(size >= MIN_BLOCK_SIZE && size % (2 * sizeof(uint64_t)) == 0);

    remove_from_free(block);
    block_t *next = next_block(block);

    if (GET_SIZE(block->header) - size < MIN_BLOCK_SIZE) {
        write_to_block(block, GET_SIZE(block->header), ALLOCATED, GET_PREV_ALLOC(block->header));
        write_to_block(next, GET_SIZE(next->header), GET_ALLOC(next->header), PREV_ALLOCATED);

        dbg_assert(GET_ALLOC(block->header) == ALLOCATED);
        dbg_assert(GET_PREV_ALLOC(next->header) == PREV_ALLOCATED);
        return;
    }
    uint64_t full_size = GET_SIZE(block->header);
    write_to_block(block, size, ALLOCATED, GET_PREV_ALLOC(block->header));
    write_to_block(next_block(block), full_size - size, FREE, PREV_ALLOCATED);

    dbg_assert(GET_ALLOC(block->header) == ALLOCATED);
    dbg_assert(GET_ALLOC(next_block(block)->header) == FREE);
    dbg_assert(GET_PREV_ALLOC(next_block(block)->header) == PREV_ALLOCATED);

    coalesce(next_block(block));
}

/**
 * @brief Searches through the heap, and finds a suitable 
 * block to allcate. It will mark the block as allocated, and 
 * then return a pointer to the user where they can store
 * data. 
 */
void *mmalloc(uint64_t size) {
    dbg_assert(check_heap());

    if (size <= 0) return NULL;

    if (heap.start == NULL) initialize_heap();

    if (size < MIN_BLOCK_SIZE) size = round_to_multiple(size, MIN_BLOCK_SIZE);

    size = round_to_multiple(size + sizeof(uint64_t), 2 * sizeof(uint64_t));

    block_t *ret;
    while ((ret = find_fit(size)) == NULL) extend_heap(size);

    split_block(ret, size);

    dbg_assert(check_heap());
    
    return header_to_payload(ret);
}

/**
 * @brief Given a pointer to a payload from the user, frees that corresponding
 * heap block. Also need to mark the next block on the heap that the previous one 
 * was now free
 */
void mfree(void *ptr) {
    dbg_assert(check_heap());

    if (ptr == NULL) return;
    block_t *block = payload_to_header(ptr);

    dbg_assert(GET_ALLOC(block->header) == ALLOCATED);
    
    write_to_block(block, GET_SIZE(block->header), FREE, GET_PREV_ALLOC(block->header));
    block_t *next = next_block(block);
    write_to_block(next, GET_SIZE(next->header), GET_ALLOC(next->header), PREV_FREE);
    coalesce(block);

    dbg_assert(check_heap());
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

uint8_t good_block_size(block_t *block) {
    if (block == heap.end) return 1;
    return (((char *)block + GET_SIZE(block->header)) <= ((char *)heap.end));
}

uint8_t footer_matches_header(block_t *block) {
    return (block->header == *get_footer(block));
}

uint8_t block_coalesced(block_t *block) {
    return (GET_PREV_ALLOC(block->header) && GET_ALLOC(next_block(block)->header));
}

#ifdef DEBUG
int check_heap(void) {
    // print_heap();
    for (block_t *block = heap.start; block != NULL; block = next_block(block)) {
        if (!good_block_size(block)) {
            fprintf(stderr, "Block + size was greater than heap.end on block at 0x%.16lx\n", (uint64_t)block);
            fprintf(stderr, "Block == 0x%.16lx, size == %lx\n", (uint64_t)block, GET_SIZE(block->header));
            fprintf(stderr, "Block + size == 0x%.16lx\n", (uint64_t)((char *)block + GET_SIZE(block->header)));
            return 0;
        }
        if (!GET_ALLOC(block->header) && !footer_matches_header(block)) {
            fprintf(stderr, "Footer on block at 0x%.16lx did not match, header: %lu, footer: %lu\n",
                   (uint64_t)block, block->header, *get_footer(block));
            return 0;
        }
        if (!GET_ALLOC(block->header) && !block_coalesced(block)) {
            fprintf(stderr, "Block at 0x%.16lx was not coalesced (prev_free is %lu, next_free is %lu)\n", 
                    (uint64_t)block, GET_PREV_ALLOC(block->header), GET_ALLOC(next_block(block)->header));
            return 0;
        }
    }
    return 1;
}

void dbg_printf(const char *fmt, ...) {
    // print_heap();
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, fmt, args);
    va_end(args);
}
#else
int check_heap(void) {
    return 1;
}
void dbg_printf(UNUSED const char *fmt, ...) {}
#endif