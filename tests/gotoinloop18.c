#include <stdio.h>
#include <stdlib.h>

int main() {
    int i, j, k;

    for (i = 0 ; i < 100 ; i++) {
        printf("1\n");

        while (j < 20) {
            printf("2\n");
            if (j == 10) {
loop1:
                printf("3\n");
            }
            if (j == 15)
                goto loop2;
            j++;
        }

        printf("4\n");

        while (k < 30) {
            printf("5\n");
            if (k == 20) {
loop2:
                printf("6\n");
            }
            if (k == 25)
                goto loop1;
            k++;
        }
    } 

    return 0;
}
