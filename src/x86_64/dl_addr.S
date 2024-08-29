section .note.GNU-stack noalloc noexec nowrite progbits

section .text
global _my_dl_addr
global _my_exit

_my_dl_addr:
    xor rax, rax
    ret

_my_exit:
    xor rdi, rdi
    mov rax, 60
    syscall
