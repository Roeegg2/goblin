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
# _goblin_call__start:
# _goblin_call__start_push_auxv:
# 	pushq (%rdx)
# 	pushq 8(%rdx)
# 	sub $16, %rdx
# 	dec %rax
# 	test %rax, %rax
# 	jne _goblin_call__start_push_auxv
# 	xor %rax, %rax
# _goblin_call__start_push_envp:
# 	pushq (%rsi)
# 	add $8, %rsi
# 	inc %rax
# 	cmp %r9, %rax
# 	jne _goblin_call__start_push_envp
# 	xor %rax, %rax
# _goblin_call__start_push_argv:
# 	pushq (%rdi)
# 	add $8, %rdi
# 	inc %rax
# 	cmp %rcx, %rax
# 	jne _goblin_call__start_push_argv

# rdi - end of argv
# rsi - _start (entry point)
# rdx - argc
_goblin_call__start:
	# when pushing AT_NULL, we only need to push NULL (ie the type (or value, both have the same value))
	movq (%rdi), %rax
	sub $16, %rdi
_goblin_call__start_push_auxv:
	# a_type
	pushq (%rdi)
	# a_val
	movq 8(%rdi), %rax
	pushq %rax 
	sub $16, %rdi
	test %rax, %rax
	jne _goblin_call__start_push_auxv
	mov $2, %r11 # once for envp, once for argv
_goblin_call__start_push_envp_argv:
	movq (%rdi), %rax
	pushq %rax
	sub $8, %rdi
	test %rax, %rax
	jne _goblin_call__start_push_envp_argv
	
	dec %r11
	test %r11, %r11
	jne _goblin_call__start_push_envp_argv
	# push argc
	pushq %rdx
	# set %rdx to atexit
	lea _goblin_atexit(%rip), %rdx
	# jump tp _start
	jmp *%rsi

	
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


