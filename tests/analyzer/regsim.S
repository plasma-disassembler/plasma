// gcc -nostdlib regsim.S -e _start -o regsim.bin

.intel_syntax noprefix
.global main
.global _start

.section .text

__noreturn:
    jmp __noreturn

_start:
    call main
    call __noreturn
    ret

main:
	push rbp

    mov rax, 0
loop:
    add rax, 1 # the analyzer should not replace by rax = 1
    cmp rax, 10
    jne loop


    mov rbx, 10
    lea rax, qword ptr [rbx + one_byte - 100]
    add rax, 90 # the analyzer mut find one_byte

	leave
    ret

one_byte: .byte 0
