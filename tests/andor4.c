#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {
    srand(time(NULL));
    int i = rand();
    int j = rand();

    if (i == 1) {
        printf("2\n");
        if (j == 2)
            goto label;
    } else {
        j--;
        if (j == 0) {
label:
            printf("1\n");
        }
    }

    return 0;
}
