#ifndef UTILS_HPP
#define UTILS_HPP

#include "types.hpp"

namespace Roee_ELF {
#define STR_LITERAL_LEN(buff) (sizeof(buff) / sizeof(char))

    int elf_perm_to_mmap_perms(u32 const elf_flags);
    s8 memcmp(const void* s1, const void* s2, const u64 n);
    void memset(void *s, const u64 type, const u64 n);
    void num_to_str(u64 num, char* buff, u32 digit_num, const u8 base);
    u64 get_digit_num(u64 num, const u8 base);

#define print_str_literal(fd, buff) (syscall_write(fd, buff, STR_LITERAL_LEN(buff)))
    void print_str_num(const s32 fd, const u64 num, const u8 base);
}

#endif
