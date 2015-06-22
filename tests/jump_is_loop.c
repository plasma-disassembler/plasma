#include <stdio.h>

int main() {
    __asm__("jmp cond");
    __asm__("myloop:");
    __asm__("inc %rax");
    __asm__("cond:");
    __asm__("jle myloop");
    __asm__("ret");
}
