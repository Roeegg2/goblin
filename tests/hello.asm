    section .text
    global _start

_start:
    mov rax, 1
    mov rdi, 1
    mov rsi, msg
    mov rdx, 10
    syscall

    mov rax, 60
    xor rdi, rdi
    syscall

    section .data

msg: db "hello, world!"