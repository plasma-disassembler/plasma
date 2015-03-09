#include <stdio.h>
#include <stdlib.h>

int main() {
    int j = 2;

    do {
        printf("%x\n", j);
        j++;
    } while (j < 10);

    return 0;
}

