#include <stdio.h>
#include <stdlib.h>

int main() {
    int i = 2;

    switch (i) {
        case 2:
            printf("2\n");
            break;
        case 3:
            printf("3\n");
            break;
        case 4:
            printf("4\n");
            break;
        case 5:
            printf("5\n");
            break;
        case 10:
            printf("10\n");
            break;
        default:
            printf("default\n");
            break;
    }

    return 0;
}
