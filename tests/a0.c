
extern int number;

void ftl_exit(int code) {
    __asm__ (
            " \
            mov %[code], %%edi \n\
            mov $60, %%rax \n\
            syscall"
            :
            : [code] "r" (code)
    );
}

void _start(void) {
    ftl_exit(number);
}
