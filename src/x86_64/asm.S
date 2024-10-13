.section .note.GNU-stack,"",@progbits

.section .text
.global _goblin_tls_init_tp
.global _goblin_tls_get_tp
.global _goblin_call__start

# rdi - end of argv
# rsi - end of envp
# rdx - end of auxv
# rcx - argc
# r8 - _start
# r9 - envp count
# LOCALS:
# rax - looper

# I know, not very efficient, but it's just a PoC. As I've already stated before, the goal of this project isn't to create something actually usefull - just to understand how thiongs work. And this is the simplest, most understandable and least error-prone way to do it.
_goblin_call__start:
	xor %rax, %rax
_goblin_call__start_push_auxv:
	pushq 8(%rdx)
	pushq (%rdx)
	add $16, %rdx
	inc %rax
	cmp $23, %rax
	jne _goblin_call__start_push_auxv
	xor %rax, %rax
_goblin_call__start_push_envp:
	pushq (%rsi)
	add $8, %rsi
	inc %rax
	cmp %r9, %rax
	jne _goblin_call__start_push_envp
	xor %rax, %rax
_goblin_call__start_push_argv:
	pushq (%rdi)
	add $8, %rdi
	inc %rax
	cmp %rcx, %rax
	jne _goblin_call__start_push_argv
	# push argc
	pushq %rcx
	# jump tp _start
	jmp *%r8

	

# rdi - receives TP (pointer to the TLS block)
_goblin_tls_init_tp:
	# systemd 64 ABI says first argument goes into %rdi
	wrfsbase %rdi
	ret

_goblin_tls_get_tp:
	mov %fs, %rax
	ret


