#include <stdlib.h>
#include <stdio.h>
int main() {
    int i, j;
    for (i = 0 ; i < 20 ; i++) {
        printf("1\n");

        for (j = 0 ; j < 30 ; j++) {
            printf("3\n");
            if (j == 2) {
                printf("4\n");
                goto next;
            }
            if (j == 3) {
                printf("8\n");
                goto next2;
            }
            printf("5\n");
        }

        printf("2\n");
    }

    printf("6\n");

next:
    printf("7\n");

next2:
    printf("9\n");

    return 0;
}
