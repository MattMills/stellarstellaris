section .text
global _start
_start:
    pop   rax
    test  rdi, rdi
    je . + 3
    mov   rax, qword [rdi]
    call   qword [rax+0x70]
    mov    byte [rbx+0x0B0], 1
    push   rax
    push   rbx
    push   rdi
    xor    rax, rax
    mov    rdi, rbx
    mov    rax, 0xdeadbeeff00d
    mov    qword rbx, [rax+0x8]
    mov    qword [rax+rbx*0x8], rdi
    inc    rbx
    mov    qword [rax+0x8], rbx
    pop    rdi
    pop    rbx
    pop    rax
    ret
_jmp:
    push rax
    mov rax, 0xdeadbeeff00d
    jmp rax
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    
