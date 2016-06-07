#include <stdlib.h>
#include <stdio.h>

int main() {
    int i, j;

    if (i == 0) {
        if (j == 0) {
            printf("exit\n");
            exit(0);
        }

        for (i = 0 ; i < 10 ; i++) {
            printf("loop\n");
        }
    }

    return 0;
}
