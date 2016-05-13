// gcc -nostdlib test.S -e _start

.intel_syntax noprefix
.global main
.global _start

.section .text

.macro ACCESS_VARS
    mov rax, [rbp - 4]
    mov rax, [rsp - 4 + 16]
.endm

// --------------------------------------------------------
// CALL TESTS
// --------------------------------------------------------

__stdcall:
	push rbp
	mov rbp, rsp
    mov rax, [rbp + 4]
    pop rbp
    pop rax
    pop rax
    pop rax
    ret

__cdecl:
	push rbp
	mov rbp, rsp
    pop rbp
    ret

__jmp_func:
    jmp __stdcall

__noreturn:
    jmp __noreturn

// --------------------------------------------------------

_start:
    call main
    call __noreturn
    ret

main:
	push rbp
	mov rbp, rsp
    sub rsp, 16

    ACCESS_VARS

	push rax
	push rbx
	push rcx
	call __stdcall

    ACCESS_VARS

	push rax
	push rbx
	push rcx
	call __cdecl
	add rsp, 8*3

    ACCESS_VARS

    push rax
    push rbx
    push rcx
    call __jmp_func

    ACCESS_VARS

	pop rbp
    ret
