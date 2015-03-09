#include <stdio.h>
#include <stdlib.h>

int main() {
    int i = time(NULL);

    while (i < 100 || i < 20 || i < 10 || i < 5) {
        printf("1\n");
        i++;
    }

    printf("2\n");

    return 0;
}
