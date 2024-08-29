section .note.GNU-stack noalloc noexec nowrite progbits

_my_dl_addr:
    xor rax, rax
    ret

_my_exit:
    xor rdi, rdi
    mov rax, 60
    syscall
