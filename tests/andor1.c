#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main(int argc, char *argv[])
{
    int i, j, k;

    while (i < 10 && j < 10 || i == k)
    {
        printf("1\n");
        while (k < 20)
            printf("2\n");
    }

    return 0;
}
