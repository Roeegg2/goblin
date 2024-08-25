// in `samples/ifunc-nolibc.c`

// this used to be part of `ftl_print`.
int ftl_strlen(char *s) {
    int len = 0;
    while (s[len]) {
        len++;
    }
    return len;
}

void ftl_print(char *msg) {
    int len = ftl_strlen(msg);

    // I just wanted to show off that, in the input/output mappings,
    // you can use any old C expression - here, a call to `ftl_strlen`
    __asm__ (
            " \
            mov      $1, %%rdi \n\t\
            mov      %[msg], %%rsi \n\t\
            mov      %[len], %%edx \n\t\
            mov      $1, %%rax \n\t\
            syscall"
            // outputs
            :
            // inputs
            : [msg] "r" (msg), [len] "r" (ftl_strlen(msg))
            );
}

// same as before
void ftl_exit(int code) {
    __asm__ (
            " \
            mov     %[code], %%edi \n\t\
            mov     $60, %%rax \n\t\
            syscall"
            : // no outputs
            : [code] "r" (code)
            );
}

// Here's the implementation of `get_msg` for the root user
char *get_msg_root() {
    return "Hello, root!\n";
}

// Here's the implementation of `get_msg` for a regular user
char *get_msg_user() {
    return "Hello, regular user!\n";
}

// C function pointer syntax is.. well, "funky" doesn't even
// start to cover it, so let's make a typedef with the type
// of `get_msg`:
typedef char *(*get_msg_t)();

// Here's our selector for `get_msg` - it'll return the
// right implementation based on the current "uid" (user ID).
static get_msg_t resolve_get_msg() {
    int uid;

    // make a `getuid` syscall. It has no parameters,
    // and returns in the `%rax` register.
    __asm__ (
            " \
            mov     $102, %%rax \n\t\
            syscall \n\t\
            mov     %%eax, %[uid]"
            : [uid] "=r" (uid)
            : // no inputs
            );

    if (uid == 0) {
        // UID 0 is root
        return get_msg_root;
    } else {
        // otherwise, it's a regular user
        return get_msg_user;
    }
}

// And here's our `get_msg` declaration, finally!
// Using the GCC-specific `ifunc` attribute.
char *get_msg() __attribute__ ((ifunc ("resolve_get_msg")));

int main() {
    // print whatever `get_msg` returns
    ftl_print(get_msg());
    return 0;
}

void _start() {
    ftl_exit(main());
}
