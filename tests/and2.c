#include <stdio.h>
#include <stdlib.h>

int main() {
    int i = 123, j = 5;

    while (1) {
        if (i != 0 && j < 10 && i != j) {
            printf("1\n");
        }
        printf("2\n");
        i++;
        if (i == 0)
            printf("3\n");
        j++;
    }

    return 0;
}



