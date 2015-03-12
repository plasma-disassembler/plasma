#include <stdio.h>
#include <stdlib.h>

int main() {
    int i = 0, j;

    for (i = 0 ; i < 1000 ; i++) {
        printf("1\n");

        j = rand();
        if (j == 1) {
            if (i < 500) {
                printf("2\n");
                if (i < 200) {
                    printf("3\n");
                    if (i == 1 || i == 2 || i == 3) {
                        printf("4\n");
                    }
                }

                else if (i == 42) {
                    while (1) {
                        printf("loooop!\n");
                    }
                }
            }
            printf("continue!\n");
            continue;
        }

        printf("5\n");
    }
    printf("6\n");

    return 0;
}




