.section .note.GNU-stack,"",@progbits

.section .text
.global _goblin_set_tp
.global _goblin_get_tp
.global _goblin_atexit

_goblin_atexit:
	movq $60, %rax
	xor %rdi, %rdi
	syscall

# rdi - receives TP (pointer to the TLS block)
_goblin_set_tp:
	movq $158, %rax
	movq %rdi, %rsi
	movq 0x1002, %rdi
	syscall
	ret

_goblin_get_tp:
	movq %fs, %rax
	ret


