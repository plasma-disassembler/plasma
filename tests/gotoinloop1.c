#include <stdio.h>
#include <stdlib.h>

int main() {
    int i, j;

    if (i == 1) {
        printf("1\n");
        goto next;
    } else {
        printf("2\n");
    }

    while (i < 1) {
        printf("loop\n");
        if (j == 6) {
            printf("3\n");
        } else {
            printf("4\n");
        }

next:
        if (j == 5) {
            printf("5\n");
        } else {
            printf("6\n");
        }
        i++;
    }

    return 0;
}
