#include <stdio.h>
#include <stdlib.h>

int main() {
    int i, j, k;

    while (i < 1) {
        printf("1\n");
next:
        while (k < 25) {

            if (i == 1) {
                printf("2\n");
                goto next;
            } else {
                printf("3\n");
            }
            k++;
        }
      i++;
    }

    return 0;
}

