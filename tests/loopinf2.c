#include <stdio.h>
#include <stdlib.h>

int main() {
    int i = 123;

    if (i > 0) {
        while (1) {
            if (i == 456)
                printf("1\n");
            i++;
        }
    } else {
        while (1) {
            if (i == 123)
                printf("2\n");
            i++;
        }
    }

    return 0;
}



