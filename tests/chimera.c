// in `elk/samples/chimera/chimera.c`
// omitted: `ftl_exit`

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

// in `elk/samples/chimera/chimera.c`


void _start() {
    ftl_exit(number);
}
