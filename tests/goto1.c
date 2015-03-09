#include <stdio.h>
#include <stdlib.h>

int main() {
    int i = rand();

    if (i == 0) {
        printf("NULL\n");
        goto err;
    }


restart:
    i = 5;
    while (i < 100) {
        printf("1\n");
        printf("2\n");
        int j = 0;
        
        while (j < 50) {
            printf("3\n");
            int tmp = rand();
            if (tmp == 1) {
                printf("restart!\n");
                goto restart;
            }
            
            if (tmp == 2) {
                printf("stop\n");
                goto err;
            }
            j++;
        }

        i++;
    }

    printf("4\n");
    printf("5\n");
    return 0;

err:
    printf("err exit\n");
    return 1;
}



