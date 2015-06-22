#include <stdio.h>

int main() {
    int i, j, k;

    if (k) {
        while (i < 30) {
            printf("1\n");
            if (j == 15) {
                printf("2\n");
                goto end;
            }
            printf("3\n");
        }
    }

    if (i == 123) {
        printf("4\n");
        goto finish;
    } else {
        printf("5\n");
    }

end:
    printf("end\n");
finish:
    printf("finish\n");

    return 0;
}
