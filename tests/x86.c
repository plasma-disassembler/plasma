/* gcc tests/x86.c -o tests/x86.bin -masm=intel */

int main() {
    __asm__("stosb");
    __asm__("stosw");
    __asm__("stosd");
    __asm__("stosq");

    __asm__("movsb");
    __asm__("movsw");
    __asm__("movsd");
    __asm__("movsq");

    __asm__("lodsb");
    __asm__("lodsw");
    __asm__("lodsd");
    __asm__("lodsq");

    __asm__("cmpsb");
    __asm__("cmpsw");
    __asm__("cmpsd");
    __asm__("cmpsq");

    __asm__("scasb");
    __asm__("scasw");
    __asm__("scasd");
    __asm__("scasq");

    __asm__("repne scasb");
    __asm__("rep stosb");

    return 0;
}
