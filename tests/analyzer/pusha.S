// gcc -nostdlib pusha.S -e _start -o pusha.bin -m32

.intel_syntax noprefix
.global main
.global _start

.section .text

.macro ACCESS_VARS
    // these two access must be the same
    mov eax, [ebp - 4]
    mov eax, [esp - 4 + 16]
.endm

__pusha_func:
    pushaw
    pushad
    pushfd
    popfd
    popad
    popaw
    ret

__noreturn:
    jmp __noreturn

_start:
    call main
    call __noreturn
    ret

main:
	push ebp
	mov ebp, esp
    sub esp, 16

    ACCESS_VARS

    call __pusha_func

    ACCESS_VARS

	pop ebp
    ret
