.section .note.GNU-stack,"",@progbits

.section .text
.global _goblin_dl_addr
.global _goblin_exit

 _goblin_dl_addr:
	xor %rax, %rax
	ret

_goblin_exit:
	xor %rdi, %rdi
	mov $60, %rax
	syscall


