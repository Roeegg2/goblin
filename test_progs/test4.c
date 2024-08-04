// Filename: simple_print.c

#include <unistd.h>

int main() {
    const char* message = "Hello, world!\n";
    write(STDOUT_FILENO, message, 14);
    return 0;
}
