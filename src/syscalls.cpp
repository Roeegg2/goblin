#include "../include/syscalls.hpp"

#include <sys/syscall.h>

namespace Roee_ELF {
    int64_t _syscall(uint64_t rax, uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t r10, uint64_t r8, uint64_t r9) {
        register uint64_t r10_val asm("r10") = r10;
        register uint64_t r8_val asm("r8") = r8;
        register uint64_t r9_val asm("r9") = r9;
        asm volatile(
            "syscall\n"
            : "=a"(rax)
            : "a"(rax), "D"(rdi), "S"(rsi), "d"(rdx)
            : "memory" // syscall might modify memory
        );

        return rax;
    }

    /*simple wrapper functions for simplicity*/
    int64_t syscall_exit(int32_t err_code) {
        return _syscall(SYS_exit, err_code);
    }

    int64_t syscall_write(uint64_t fd, const char* buff, uint64_t count) {
        return _syscall(SYS_write, fd, (uint64_t)buff, count);
    };

    int64_t syscall_read(uint64_t fd, char* buff, uint64_t count) {
        return _syscall(SYS_read, fd, (uint64_t)buff, count);
    };

    int64_t syscall_open(const char* filename, uint64_t flags, uint64_t mode) {
        return _syscall(SYS_open, (uint64_t)filename, flags, mode);
    };

    int64_t syscall_close(uint64_t fd) {
        return _syscall(SYS_close, fd);
    };

    int64_t syscall_lseek(uint64_t fd, uint64_t offset, uint64_t origin) {
        return _syscall(SYS_lseek, fd, offset, origin);
    };

    int64_t syscall_mmap(uint64_t addr, uint64_t length, uint64_t prot, uint64_t flags, uint64_t fd, uint64_t offset) {
        return _syscall(SYS_mmap, addr, length, prot, flags, fd, offset);
    };

    int64_t syscall_munmap(uint64_t addr, uint64_t length) {
        return _syscall(SYS_munmap, addr, length);
    };

    int64_t syscall_mprotect(uint64_t addr, uint64_t length, uint64_t prot) {
        return _syscall(SYS_mprotect, addr, length, prot);
    };

    int64_t syscall_fork(void) {
        return _syscall(SYS_fork);
    };
};
