#include <stdio.h>
#include <stdlib.h>

int main() {
    int i = 123, j = 5;

    while (i < 100 && i < 50 && i < 20 && i < 10) {
        if (i == 5)
            printf("1\n");
        i++;
    }
    printf("2\n");

    return 0;
}




