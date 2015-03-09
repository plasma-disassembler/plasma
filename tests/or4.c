#include <stdio.h>
#include <stdlib.h>

int main() {
    int i = 0, j;

    if (i < 200) {
        printf("1\n");
        if (i == 1 || i == 2 || i == 3) {
            printf("2\n");
        }
    }
    printf("3\n");

    return 0;
}




