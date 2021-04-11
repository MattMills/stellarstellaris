section .text
global _start
_start:
    push   rbx
    mov    byte [rdi+0x0B0], 1
    mov    rax, 0xdeadbeeff00d
    mov    qword rbx, [rax+0x8]
    mov    qword [rax+rbx*0x8], rdi
    inc    rbx
    mov    qword [rax+0x8], rbx
    pop    rax
    mov    rbx, rdi
    mov    rdi, qword [rbx+0x128]
    push   rbx
    xor    rbx, rbx
    mov    rbx, 0x000000000220436d
    jmp    rbx
_jmp:
    push   rax
    mov    rax, 0xdeadbeeff00d
    jmp    rax
    pop    rbx
    nop
    nop
    nop
    nop
    
