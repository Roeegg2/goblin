        global _start

        section .text

_start:
        ; this used to be a `lea rax, [rel zero]` plus a `lea rax, [rax]`
        mov rax, zero

        xor rdi, rdi    ; return code 0
        mov rax, 60     ; exit syscall
        syscall

        section .bss

pad:    resq 65536
zero:   resq 16
