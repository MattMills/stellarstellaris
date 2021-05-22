section .text
global _start
_start:
	push rbp
	push r15
	push r14
	push r13
	push r12  
	push rbx
	sub rsp, 0x78
	mov r15, 0xdeadbeefcafe ; pointer base
	cmp byte [r15+0x38], 0x1
	je .skip
	mov qword [r15], r8
	mov qword [r15+0x8], r9
	mov qword [r15+0x10], rdi
	mov qword [r15+0x18], rsi
	mov qword [r15+0x20], rdx
	mov qword [r15+0x28], rcx
	inc qword [r15+0x30]
	mov byte [r15+0x38], 0x1
.skip:
	add rsp, 0x78
	pop rbx
	pop r12
	pop r13
	pop r14
	pop r15
	pop rbp
	ret
_loadstub:
	push rbp
	mov r15, 0xdeadbeefcafe
	mov r8, qword [r15]
	mov r9, qword [r15+0x8]
	mov rdi, qword [r15+0x10]
	mov rsi, qword [r15+0x18]
	mov rdx, qword [r15+0x20]
	mov rcx, qword [r15+0x28]
	add r15, 0x100
	call r15
	
	pop rbp
	ret
