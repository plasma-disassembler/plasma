// same as tests/andor3.c but compiled with -O3
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {
    srand(time(NULL));
    int i = rand();
    int j = rand();

    if (i == 1) {
        i--;
        if (j == 0) {
label:
            printf("1\n");
        }
    } else {
        printf("2\n");
        if (i == 2)
            goto label;
    }

    return 0;
}
