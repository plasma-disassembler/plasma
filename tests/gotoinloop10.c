#include <stdio.h>
#include <stdlib.h>

int main() {
    int i, j, k;

    if (i == 1) {
        printf("1\n");
        goto next;
    } else {
        printf("2\n");
    }


    while (i < 123) {
        while (j < 456) { 
            while (k < 789) {
                if (i == j) {
next:
                    printf("3\n");
                } else {
                    if (j == k) {
                        printf("4\n");
                    } else if (i == k) {
                        printf("5\n");
                    }
                }
                printf("6\n");
            }
            printf("7\n");
        }
        printf("8\n");
    }

    return 0;
}
