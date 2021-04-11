section .text
global _start
_start:
    pop    rax
    mov    rax, qword [rdi]
    call   qword [rax+0x78]
    mov    byte [rbx+0x0B0], 1
    push   rax
    push   rdi
    xor    rdi,rdi
    mov    rdi,rbx
    xor    rbx,rbx
    mov    rax, 0xdeadbeeff00d
    mov    qword rbx, [rax+0x8]
    mov    qword [rax+rbx*0x8], rdi
    inc    rbx
    mov    qword [rax+0x8], rbx
    pop    rdi
    pop    rax
    pop    rbx
    ret
_jmp:
    push rax
    mov rax, 0xdeadbeeff00d
    jmp rax
    
