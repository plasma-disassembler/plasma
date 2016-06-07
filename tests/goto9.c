#include <stdlib.h>
#include <stdio.h>

int main() {
    int i;

    for (;;) {
        if (i > 0) {
            if (i == 5)
                goto end;
            printf("123\n");
        }
        else {
            if (i == -5)
                goto end;
            printf("456\n");
        }
        printf("789\n");
    }

end:
    return 0;
}
