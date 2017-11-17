#include <stdio.h>
#include <stdlib.h>

void func1() {
    int i;
    if (i < 5) {
        printf("1\n");
        exit(0);
    }
    printf("2\n");
    return;
}

void func2() {
    int i;
    if (i < 5) {
        printf("1\n");
    }
    printf("2\n");
    return;
}

int main() {
    int i, j, k, l, m;

    if (i != 0) {
        if (j != 1) {
            if (k != 2) {
                printf("1\n");
            }
            else {
                printf("2\n");
            }
        }
        else {
            printf("3\n");
        }
    }
    else {
        printf("4\n");
    }

    func1();
    func2();
    return 0;
}
