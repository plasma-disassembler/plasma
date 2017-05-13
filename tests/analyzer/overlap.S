// gcc -nostdlib overlap.S -e _start

.intel_syntax noprefix
.global main
.global _start

.section .text

obfuscated_call:
    ret


overlap_1:
    mov eax, 0xBBC10300
    mov ecx, 0x05000000
    add eax, ecx
    jmp $-10
    add eax, ebx
    ret


overlap_2:
    xor ecx, ecx
    dec ecx
    inc ecx
    jnz $+3
    .byte 0xb8 // this is the mnemonic for a mov eax

    // do some stuff
    xor ecx, ecx
    loop:
    call obfuscated_call
    inc ecx
    cmp ecx, 15
    jle loop
    ret


_start:
    call overlap_1
    call overlap_2
    ret


