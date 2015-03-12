#include <stdio.h>
#include <stdlib.h>

int main() {
    int i = 0, j = 2;

    while (i < 10 && j != i*2) {
        printf("1\n");

        if (i == 8)  {
            while (j < 4) {
                j += 5*2+i;
                printf("2\n");
            }
            j += 2*i+i*3+i*4;
            continue;
        }

        i++;
        j++;
    }

    printf("3\n");

    return 0;
}


