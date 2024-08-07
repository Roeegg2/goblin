#ifndef SYSCALLS_HPP
#define SYSCALLS_HPP

#include "types.hpp"

#ifdef __amd64__
namespace Roee_ELF {
    constexpr u8 STDOUT_FD = 1;
    constexpr u8 STDIN_FD = 2;
    constexpr u8 STDERR_FD = 3;

    s64 _syscall(u64 rax, u64 rdi, u64 rsi = 0, u64 rdx = 0, u64 r10 = 0, u64 r8 = 0, u64 r9 = 0);
    s64 syscall_exit(s32 err_code);
    s64 syscall_write(u64 fd, const char* buff, u64 count);
    s64 syscall_read(u64 fd, char* buff, u64 count);
    s64 syscall_open(const char* filename, u64 flags, u64 mode);
    s64 syscall_close(u64 fd);
    s64 syscall_lseek(u64 fd, u64 offset, u64 origin);
    s64 syscall_mmap(u64 addr, u64 length, u64 prot, u64 flags, u64 fd, u64 offset);
    s64 syscall_munmap(u64 addr, u64 length);
    s64 syscall_mprotect(u64 addr, u64 length, u64 prot);
};

#else
#error "Unsupported architecture"
#endif

#endif
