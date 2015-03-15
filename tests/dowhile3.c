#include <stdio.h>
#include <stdlib.h>

int main() {
    int i = 123, j = 5, k = 1;

    do {
        i++;
        do {
            j++;
            do {
                k++;
            } while (k < 4);
        } while (j < 2);
    } while (i < 5);

    return 0;
}





