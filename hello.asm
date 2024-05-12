global _start

section .data
    msg db 'Hello, World!', 0

section .text
_start:
    mov rdi, 1
    mov rsi, msg
    mov rdx, 13
    mov rax, 1
    syscall

    xor rdi, rdi
    mov rax, 60
    syscall