#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    int i, j, k;
    do {
        if (i == 1)
            for(j = 0 ; j < k ; k++)
                printf("1\n");

        if (i == 2)
            printf("2\n");
    } while (i != 3);

    return 0;
}
