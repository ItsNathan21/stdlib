#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <inttypes.h>
#include <time.h>
#include <string.h>
#include <dirent.h>
#include "malloc.h"


#define UNUSED __attribute__((unused))
#define ITERS (10)
#define MAX_LINELENGTH (100)

typedef enum {
    MALLOC = 'M', 
    FREE = 'F'
} operation_t;


void run_trace(char *tracefile) {
    FILE *trace = fopen(tracefile, "r");

    if (trace == NULL) {
        fprintf(stderr, "Failed to open file with name %s\n", tracefile);
        exit(1);
    }

    char LINEBUF[MAX_LINELENGTH];

    int64_t trace_array_size;

    if (!fgets(LINEBUF, MAX_LINELENGTH, trace)) {
        fprintf(stderr, "First gets call failed!\n");
        exit(1);
    }

    sscanf(LINEBUF, "%ld", &trace_array_size);

    int8_t *trace_array[trace_array_size];
    int8_t trace_array_check[trace_array_size];

    memset(trace_array_check, 0, trace_array_size);

    int64_t size_to_malloc, trace_array_index;
    int8_t operation;

    while (fgets(LINEBUF, MAX_LINELENGTH, trace)) {
        if (LINEBUF[0] == MALLOC) {
            sscanf(LINEBUF, "%c %ld %ld", &operation, &trace_array_index, &size_to_malloc);
            trace_array[trace_array_index] = mmalloc(size_to_malloc);
            trace_array_check[trace_array_index] = 1;
            memset(trace_array[trace_array_index], 1, size_to_malloc);
        }
        else if (LINEBUF[0] == FREE) {
            sscanf(LINEBUF, "%c %ld", &operation, &trace_array_index);
            if (trace_array_check[trace_array_index] == 0) {
                fprintf(stderr, "Trying to free a non-malloc'ed block\n");
                fprintf(stderr, "Line is %s, trace_array_check[trace_array_index] = %d\n",
                        LINEBUF, trace_array_check[trace_array_index]);
                exit(1);
            }
            mfree(trace_array[trace_array_index]);
            trace_array_check[trace_array_index] = 0;
        }
    }
    for (int64_t i = 0; i < trace_array_size; i++) {
            if (trace_array_check[i]) mfree(trace_array[i]);
        }
    fclose(trace);
}


int main(UNUSED int argc, UNUSED char **argv) {

    struct timeval start, end;

    const char *tracepath = "traces/";

    DIR *trace_dir = opendir(tracepath);

    if (trace_dir == NULL) {
        fprintf(stderr, "ERROR opening dir at %s\n", tracepath);
        exit(1);
    }

    struct dirent *curr_trace;

    gettimeofday(&start, NULL);

    printf("[ "); fflush(stdout);
    while ((curr_trace = readdir(trace_dir)) != NULL) {
        char *name = curr_trace->d_name;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;

        char full_path[512];
        snprintf(full_path, sizeof(full_path), "%s/%s", "traces", name);
        run_trace(full_path);
        printf("* ");
        fflush(stdout);
    }

    printf("]\n"); fflush(stdout);

    closedir(trace_dir);

    gettimeofday(&end, NULL);

    double elapsed = (end.tv_sec - start.tv_sec)
                   + (end.tv_usec - start.tv_usec) / 1e6;

    printf("Elapsed time: %.16f seconds\n", elapsed);

    return 0;
} 