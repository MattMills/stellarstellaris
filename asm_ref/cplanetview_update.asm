section .text
global _start
_start:
    xor    rax, rax
    mov    rax, 0x3403b84 ; address of outliner frame counter
    cmp    dword [rax], 0x2
    db     0x74, 0x5
    add    rsp, 0x8
    ret
    pop    rax
    push   rbp
    mov    rbp, rsp
    push   r15
    push   r14
    push   r13
    push   r12
    push   rbx
    sub    rsp, 0x508
    push   rax
    ret
_jmp:
    xor rax,rax
    mov rax, 0xdeadbeeff00d
    call rax
    nop
    nop
    
