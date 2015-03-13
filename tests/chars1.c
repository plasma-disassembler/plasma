#include <stdio.h>
#include <stdlib.h>

int main() {
    unsigned char c = 0;

    if (c == 'a')
        printf("1\n");
    else if (c == 'b')
        printf("2\n");
    else if (c == 'c')
        printf("3\n");
    else if (c == 250)
        printf("4\n");
    else if (c == '\n')
        printf("5\n");

    return 0;
}



