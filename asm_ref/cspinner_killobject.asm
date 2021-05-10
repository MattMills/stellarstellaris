section .text
global _start
_start:
    mov    rax, 0xdeadbeeff00d
    mov    qword rbx, [rax+0x8]
    mov    qword [rax+rbx*0x8], rdi
    inc    rbx
    mov    qword [rax+0x8], rbx

    mov    rbx, rdi
    mov    byte [rbx+0xb0], 0x1
    mov    rdi, qword [rbx+0x128]

    ret
_jmp:
    push   rbx
    mov    rax, 0xdeadbeeff00d
    call    rax
    nop
    nop
    nop
    nop
    nop

