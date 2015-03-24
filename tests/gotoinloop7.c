#include <stdio.h>
#include <stdlib.h>

int main() {
    int i, j, k;

    while (i < 1) {
        printf("loop\n");

        if (i == 1) {
            printf("1\n");
            goto next;
        } else {
            printf("2\n");
        }

        while (k < 25) {
            for (j = 0 ; j < 123 ; j++) {
                printf("for\n");
next:
                printf("3\n");
            }
        }
      i++;
    }

    return 0;
}

