#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main(int argc, char *argv[]) {
    int i, j, k;

    do
    {
        if (k == 1)
        {
            while (j > 0)
            {
                printf("1\n");
                for (i = 0 ; i < 50 ; i++) {
                    printf("2\n");
                }
            }
        }
    } while (k < 50);

    return 0;
}
