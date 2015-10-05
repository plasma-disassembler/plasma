#include <stdio.h>
#include <stdlib.h>

int main() {
    __asm__("next: jmp next");
    return 0;
}
