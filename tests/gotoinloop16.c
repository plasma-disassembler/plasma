#include <stdio.h>
#include <stdlib.h>

int main() {
    int i, j;

    if (i == 1337) {
        while (i < 15) {
            if (i == 2) {
                printf("1\n");
                goto next;
            }
            i++;
        }
    }

    while (i < 15) {
next:
        printf("2\n");
        i++;
    }

    return 0;
}
