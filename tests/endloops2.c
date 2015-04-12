#include <stdio.h>
#include <stdlib.h>

int main() {
    int i, j, k;

    while (i < 111) {
        if (i == 0) {
            if (j == 1) {
                printf("0 1\n");
            } else {
                printf("0 2\n");
            }
            goto label1;
        }

        if (i == 10) {
            if (j == 1) {
                printf("1 1\n");
            } else {
                printf("1 2\n");
            }
            break;
        }

        if (i == 15) {
            printf("goto exit\n");
            goto exit;
        }

        if (i == 20) {
            if (j == 1) {
                printf("2 1\n");
            } else {
                printf("2 2\n");
            }
exit:
            __asm__("leave");
            __asm__("ret");
        }

        if (i == 30) {
            if (j == 1) {
                printf("3 1\n");
            } else {
                printf("3 2\n");
            }
            goto label2;
        }

        if (i == 40) {
            while (1) {
                if (k == 1) {
                    printf("loop1 1\n");
                } else {
                    printf("loop1 2\n");
                }
            }
        }
    }

    printf("end\n");

    if (i == 1337) {
        while (1) {
            printf("loop2\n");
        }
    }

label1:
    if (j == 1) {
        printf("label1 1\n");
    } else {
        printf("label1 2\n");
    }

    for (i = 0 ; i < 100 ; i++) {
        if (i == 50) {
            printf("for 1\n");
        } else {
            printf("for 2\n");
        }
    }

label2:
    if (j == 1) {
        printf("label2 1\n");
    } else {
        printf("label2 2\n");
    }

    return 0;
}



