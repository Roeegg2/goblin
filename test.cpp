#include "syscalls.hpp"
#include <sys/fcntl.h>
#include <sys/syscall.h>

int main(int argc, char** argv) {
    const char* buf = "Hello, World!\n";
    int fd = Roee_ELF::syscall_open("test.txt", O_CREAT | O_RDWR, 0666);
    Roee_ELF::syscall_write(fd, buf, 14);
    Roee_ELF::syscall_close(fd);
    Roee_ELF::syscall_exit(0);
}