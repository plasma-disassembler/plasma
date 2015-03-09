#include <stdio.h>
#include <stdlib.h>

int main() {
    int i = 123;

    for (i = 0 ; i < 10 ; i++) {
        int j = 0; 
        while (j < 10) {
            printf("1\n");
            j++;
        }
        while (j < 20) {
            printf("2\n");
            j++;
        }
    }

    printf("3\n");

    return 0;
}



