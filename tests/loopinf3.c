#include <stdio.h>
#include <stdlib.h>

int main() {
    int i = 123;

    if (i > 0)
        printf("1\n");
    else {
        while (1) {
            if (i == 456)
                printf("2\n");
            i++;
        }
    }

    printf("3\n");

    return 0;
}



