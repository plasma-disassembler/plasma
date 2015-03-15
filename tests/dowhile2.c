#include <stdio.h>
#include <stdlib.h>

int main() {
    int i = 123, j = 5;

    do {
        i++;
        do {
            j++;
        } while (j < 5);
    } while (i < 10);

    return 0;
}






