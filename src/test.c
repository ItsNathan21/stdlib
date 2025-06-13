#include <stdio.h>
#include <stdlib.h>
#include "malloc.h"
#include <inttypes.h>

#define UNUSED __attribute__((unused))

int main(int argc, UNUSED char **argv) {

    uint8_t *A;
    for (int i = 0; i < argc * 1000; i++) {
        A = mcalloc(i, sizeof(uint8_t));
        if (A == NULL) break;
        // for (int j = 0; j < i; j++) {
        //     A[j] = 0x9;
        // }
        for (int j = 0; j < i; j++) {
            if (A[j] != 0) perror("Failed storing data\n");
        }
        A = mrealloc(A, 2 * i);
        for (int j = 0; j < 2 * i; j++) {
            if (j >= i) A[j] = 0x9;
        }
        for (int j = 0; j < 2 * i; j++) {
            if (j >= i && A[j] != 0x9) perror("Failed storing realloc'ed data\n");
            else if (A[j] != 0) perror("Zereo'ed out data did not make it over\n");
        }
        mfree(A);
    }
    return 0;
} 