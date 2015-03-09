#include <stdio.h>
#include <stdlib.h>

int main() {
    int i = time(NULL);

    while (i < 100 || i < 20 || i < 10 || i < 5) {
        if (i == 55)
            printf("1\n");
        else {
            printf("2\n");
            break;
        }
        i++;
    }

    printf("3\n");

    return 0;
}

