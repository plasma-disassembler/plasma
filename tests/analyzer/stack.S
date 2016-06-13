// gcc -nostdlib stack.S -e _start -o stack.bin

.intel_syntax noprefix
.global main
.global _start

.section .text

.macro ACCESS_VARS
    // these two access must be the same
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

__leave_func:
	push rbp
	mov rbp, rsp
    nop
    nop
    nop
    nop
    leave
    ret

test_frame_size:
	push rbp
	mov rbp, rsp
    xor rax, rax
    add rax, 32
    sub rsp, rax
    leave
    ret

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

	push rax
	push rbx
	push rcx
    call __leave_func
	add rsp, 8*3

    ACCESS_VARS

    call test_frame_size

    ACCESS_VARS

	push rax
	call __cdecl
    pop rax

    ACCESS_VARS

	leave
    ret
