section .text
global _start
_start:
    mov    byte [rdi+0x0B0], 1
    push   rbx
    mov    rax, 0xdeadbeeff00d
    mov    qword rbx, [rax+0x8]
    mov    qword [rax+rbx*0x8], rdi
    inc    rbx
    mov    qword [rax+0x8], rbx
    pop    rax
    pop    rbx
    ret
_jmp:
    push rax
    mov rax, 0xdeadbeeff00d
    jmp rax
