.section .note.GNU-stack,"",@progbits

.section .text
.globl _goblin_tls_init_tp
.globl _goblin_tls_get_tp

# rdi - receives TP (pointer to the TLS block)
_goblin_tls_init_tp:
	# systemd 64 ABI says first argument goes into %rdi
	wrfsbase %rdi
	ret

_goblin_tls_get_tp:
	mov %fs, %rax
	ret
