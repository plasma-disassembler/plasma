#include <stdio.h>
#include <stdlib.h>

int main() {
    int i = 123, j = 5;

    while (i < 100) {
        if (i == 5) {
            printf("1\n");
            return 1;
        }
        if (i == 6) {
            printf("2\n");
            return 2;
        }
        i++;
    }
    printf("3\n");

    return 0;
}

