#include <stdio.h>
#include <stdlib.h>

int main() {
    int i, j;

    if (i == 1) {
        printf("1\n");
        while (i < 10) {
            if (i == 2)
                goto next;
        }
        printf("2\n");
        __asm__("ret");
    }

    while (j < 15) {
next:
        printf("3\n");
    }

    return 0;
}
