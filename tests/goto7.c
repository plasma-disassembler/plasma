#include <stdlib.h>
#include <stdio.h>
int main() {
    int i = 0;

    while (i < 20) {
        printf("1\n");
        if (i == 15) {
            printf("2\n");
            int j;
            for (j = 0 ; j < 10 ; j++) {
                printf("3\n");
                if (j == 5) {
                    printf("4\n");
                    if (i == 2) {
                        printf("foo\n");
                    }
                    else {
                        printf("bar\n");
                    }
                    printf("11\n");
                }
                else {
                    printf("5\n");
                    goto out;
                }
            }
            printf("6\n");
        }
out:
        printf("7\n");
        if (i == 16) {
            printf("8\n");
        }
        else {
            printf("9\n");
        }
        printf("10\n");
        i++;
    }

    return 0;
}

