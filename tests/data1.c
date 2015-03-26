#include <stdio.h>
#include <stdlib.h>

char c1[] = {1,2,3,4,5,6,7,8,9};

int main() {
    static char c2[] = {'a', 'b'};
    char *p1 = c1;
    char *p2 = c2;
    return 0;
}

