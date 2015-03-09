#include <stdio.h>
#include <stdlib.h>

int main() {
    int i = 123, j = 5;

    if (i != 0 && i > 1 && i > 2) {
        if (j != 0 && j > 1 && j > 2)
            printf("1\n");
        else
            printf("2\n");
    }
    else {
        printf("3\n");
    }

    printf("4\n");

    return 0;
}



