#ifndef SYSCALLS_HPP
#define SYSCALLS_HPP

#include <stdint.h>

#ifdef __amd64__
namespace Roee_ELF {
    constexpr uint8_t STDOUT_FD = 1;
    constexpr uint8_t STDIN_FD = 2;
    constexpr uint8_t STDERR_FD = 3;

    int64_t _syscall(uint64_t rax, uint64_t rdi = 0, uint64_t rsi = 0, uint64_t rdx = 0, uint64_t r10 = 0, uint64_t r8 = 0, uint64_t r9 = 0);
    int64_t syscall_exit(int32_t err_code);
    int64_t syscall_write(uint64_t fd, const char* buff, uint64_t count);
    int64_t syscall_read(uint64_t fd, char* buff, uint64_t count);
    int64_t syscall_open(const char* filename, uint64_t flags, uint64_t mode);
    int64_t syscall_close(uint64_t fd);
    int64_t syscall_lseek(uint64_t fd, uint64_t offset, uint64_t origin);
    int64_t syscall_mmap(uint64_t addr, uint64_t length, uint64_t prot, uint64_t flags, uint64_t fd, uint64_t offset);
    int64_t syscall_munmap(uint64_t addr, uint64_t length);
    int64_t syscall_mprotect(uint64_t addr, uint64_t length, uint64_t prot);
    int64_t syscall_fork(void);
};

#else
#error "Unsupported architecture"
#endif

#endif
