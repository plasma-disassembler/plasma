#include <stdio.h>
#include <stdlib.h>

int main() {
    int i = 123;

    if (i > 0) {
        if (i == 5) {
            printf("1\n");
        } else if (i == 6) {
            printf("2\n");
        } else {
            if (i == 7)
                printf("3\n");
            else
                printf("4\n");
        }
    }

    printf("5\n");

    return 0;
}

