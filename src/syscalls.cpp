#include "../include/syscalls.hpp"

#include <sys/syscall.h>

namespace Roee_ELF {
    s64 _syscall(u64 rax, u64 rdi, u64 rsi, u64 rdx, u64 r10, u64 r8, u64 r9) {
        register u64 r10_val asm("r10") = r10;
        register u64 r8_val asm("r8") = r8;
        register u64 r9_val asm("r9") = r9;
        asm volatile(
            "syscall\n"
            : "=a"(rax)
            : "a"(rax), "D"(rdi), "S"(rsi), "d"(rdx)
            : "memory" // syscall might modify memory
        );

        return rax;
    }

    /*simple wrapper functions for simplicity*/
    s64 syscall_exit(s32 err_code) {
        return _syscall(SYS_exit, err_code);
    }

    s64 syscall_write(u64 fd, const char* buf, u64 count) {
        return _syscall(SYS_write, fd, (u64)buf, count);
    };

    s64 syscall_read(u64 fd, char* buf, u64 count) {
        return _syscall(SYS_read, fd, (u64)buf, count);
    };

    s64 syscall_open(const char* filename, u64 flags, u64 mode) {
        return _syscall(SYS_open, (u64)filename, flags, mode);
    };

    s64 syscall_close(u64 fd) {
        return _syscall(SYS_close, fd);
    };

    s64 syscall_lseek(u64 fd, u64 offset, u64 origin) {
        return _syscall(SYS_lseek, fd, offset, origin);
    };

    s64 syscall_mmap(u64 addr, u64 length, u64 prot, u64 flags, u64 fd, u64 offset) {
        return _syscall(SYS_mmap, addr, length, prot, flags, fd, offset);
    };

    s64 syscall_munmap(u64 addr, u64 length) {
        return _syscall(SYS_munmap, addr, length);
    };

    s64 syscall_mprotect(u64 addr, u64 length, u64 prot) {
        return _syscall(SYS_mprotect, addr, length, prot);
    };
};
