#include <stdio.h>
#include <stdlib.h>

int main() {
    int i, j;

    if (i == 1) {
        i--;
        if (i == 0) {
label:
            printf("1\n");
        }
    } else {
        printf("2\n");
        if (i == 2)
            goto label;
    }

    return 0;
}
