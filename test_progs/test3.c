// Filename: simple_print.c

#include <unistd.h>

int main() {
    const char* message = "Hello, world!\n";
    asm volatile(
        "mov $1, %%rax\n"
        "mov $1, %%rdi\n"
        "mov %0, %%rsi\n"
        "mov $14, %%rdx\n"
        "syscall\n"
        :
        : "r"(message)
        : "%rax", "%rdi", "%rsi", "%rdx"
    );
    return 0;
}
