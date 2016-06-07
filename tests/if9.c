#include <stdio.h>
#include <stdlib.h>

int main() {
    int i, j, k;

    while (i < 30) {
        if (i == j) {
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

    return 0;
}
