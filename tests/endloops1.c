#include <stdio.h>
#include <stdlib.h>

int main() {
    int i, j;

    while (i < 10) {
        printf("1\n");
        if (i == 1)
            break;
    }

    while (i < 20) {
        printf("2\n");
    }


    return 0;
}
