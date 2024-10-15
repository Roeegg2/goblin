.section .note.GNU-stack,"",@progbits

.section .text
.global _goblin_tls_init_tp
.global _goblin_tls_get_tp
.global _goblin_atexit

_goblin_atexit:
	mov $60, %rax
	xor %rdi, %rdi
	syscall

# rdi - receives TP (pointer to the TLS block)
_goblin_tls_init_tp:
	# systemd 64 ABI says first argument goes into %rdi
	wrfsbase %rdi
	ret

_goblin_tls_get_tp:
	mov %fs, %rax
	ret


