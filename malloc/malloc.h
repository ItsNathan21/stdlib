#include <inttypes.h>

void *mmalloc(uint64_t size);

void *mcalloc(uint64_t num_elements, uint64_t size);

void *mrealloc(void *ptr, uint64_t size);

void mfree(void *ptr);