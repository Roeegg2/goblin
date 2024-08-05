int main() {
    const char* str = "Hello, World!\n";

    int a = 4;
    if (a == 4) {
        a = 5;
    } else {
        a = 6;
    }
    
    asm volatile (
        "mov $1, %%rax\n"
        "mov $1, %%rdi\n"
        "mov %0, %%rsi\n"
        "mov $14, %%rdx\n"
        "syscall\n"
        :
        : "r"(str)
        : "rax", "rdi", "rsi", "rdx"
    );

    asm volatile (
        "mov $60, %%rax\n"
        "xor %%rdi, %%rdi\n"
        "syscall\n"
        :
        :
        : "rax", "rdi"
    );
}