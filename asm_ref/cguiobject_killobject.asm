llsection .text
global _start
_start:
    mov    byte [rdi+0x0B0], 1
    push   rbx
    mov    rax, 0xdeadbeeff00d
    mov    qword rbx, [rax+0x8]
    mov    qword [rax+rbx*0x8], rdi
    inc    rbx
    mov    qword [rax+0x8], rbx
    pop    rbx
    pop    rax
    ret
_jmp:
    push rax
    mov rax, 0xdeadbeeff00d
    jmp rax
_loop:
    
