global _start

section .data
    msg db 'yooooo my broda', 0

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