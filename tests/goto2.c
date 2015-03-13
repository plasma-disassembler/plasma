#include <stdio.h>
#include <stdlib.h>

int main() {
    int i = 0, j = 0, k = 0;

    if (i == 0) {
        if (k == 5) {
            printf("1\n");
            goto label;
        }
        goto end;
    } else {
        printf("2\n");
    }

    printf("3\n");

label:
    printf("4\n");

end:
    return 0;
}




