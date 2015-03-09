#include <stdio.h>
#include <stdlib.h>

int main() {
    int i = 123, j;

    if (i > 0) {
        for (i = 0 ; i < 10 ; i++) {
            for (j = 0 ; j < 5 ; j++) {
                if (i == j)
                    printf("1\n");
            }
        }
        printf("2\n");
    }

    printf("3\n");

    return 0;
}


