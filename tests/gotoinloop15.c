#include <stdio.h>
#include <stdlib.h>

int main() {
    int i, j;

    if (i == 1337) {
        printf("1\n");
        goto next;
    }

    while (i < 15) {
        j = 0;
        while (j < 30) {
            printf("2\n");
            j++;
        }
        printf("3\n");
        j = 0;
        while (j < 20) {
            if (j == 10) {
next:
                printf("4\n");
            }
            j++;
        }
        printf("5\n");
        j = 0;
        while (j < 30) {
            printf("6\n");
            j++;
        }
        i++;
    }

    return 0;
}

