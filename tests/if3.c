#include <stdio.h>
#include <stdlib.h>

int main() {
    int i = 0, j = 0, k = 0;

    while (i < 8) {
        printf("1\n");

        if (j > 10) {
            k = 0;
        } else {
            k++;
        }

        i++;
        printf("2\n");
    }

    return 0;
}



