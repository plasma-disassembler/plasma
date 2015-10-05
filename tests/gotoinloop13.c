#include <stdio.h>
#include <stdlib.h>

int main() {
    int i, j;

    if (i == 1337) {
        printf("1\n");
        goto next;
    }

    while (i < 15) {
        printf("2\n");
next:
        for (j = 0 ; j < 20 ; j++) {
            printf("3\n");
        }
        i++;
    }

    return 0;
}
