#include <stdio.h>
#include <stdlib.h>

int main() {
    int i, j;

    if (i == 1) {
        printf("1\n");
        goto next_1;
    } else if (i == 2) {
        printf("2\n");
        goto next_2;
    } else {
        printf("3\n");
    }

    while (i < 10) {
        printf("loop\n");
        if (j == 111) {
            printf("3\n");
        } else {
            printf("4\n");
        }

next_1:
        if (j == 222) {
            printf("5\n");
        } else {
            printf("6\n");
        }

next_2:
        if (j == 333) {
            printf("7\n");
        } else {
            printf("8\n");
        }

        i++;
    }

    return 0;
}

