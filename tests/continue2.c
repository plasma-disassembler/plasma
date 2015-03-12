#include <stdio.h>
#include <stdlib.h>

int main() {
    int i = 0, j = 2, z;

    for (z = 0 ; z < 20 ; z++) {
        while (i < 10 && j != i*2) {
            printf("1\n");

            if (i == 8) {
                printf("2\n");
                continue;
            }

            if (j == 5) {
                while (1) {
                    printf("3\n");
                }
            }

            i++;
            j++;
        }

        if (z == 15) {
            printf("4\n");
            continue;
        }

        printf("5\n");
    }

    printf("6\n");

    return 0;
}



