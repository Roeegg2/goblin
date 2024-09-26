.section .note.GNU-stack,"",@progbits

.section .text
.global _goblin_tls_init_tp
.global _goblin_tls_get_tp
.global _goblin_call__start

# rdi - argc
# rsi - argv
# rdx - atexit shit
# rcx - address of _start
# r8 - total amount to push

# rax - main looper
_goblin_call__start:
	# push garbage
	push %rax 
_goblin_start_push_loop:
	push (%rsi, %r8, 8)
	dec %r8
	test %r8, %r8
	jne _goblin_start_push_loop
	push %rdi
	jmp *%rcx


# _goblin_call__start:
# 	push %rdi
# 	
# 	xor %rax, %rax
# _goblin_call__start_args_loop:
# 	cmp %rax, %rdi
# 	je _goblin_call__start_env_loop
# 	push (%rsi, %rax, LP_SIZE)
# 	inc %rax
# 	jmp _goblin_call__start_args_loop
# _goblin_call__start_env_loop:
# 	inc %rax
# 	mov (%rsi, %rax, LP_SIZE), %r12
# 	push %r12
# 	test %r12, %r12
# 	jne _goblin_call__start_env_loop
#
# 	# jump to _start
# 	jmp *%rcx

# rdi - receives TP (pointer to the TLS block)
_goblin_tls_init_tp:
	# systemd 64 ABI says first argument goes into %rdi
	wrfsbase %rdi
	ret

_goblin_tls_get_tp:
	mov %fs, %rax
	ret


