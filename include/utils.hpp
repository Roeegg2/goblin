#ifndef UTILS_HPP
#define UTILS_HPP

#include "types.hpp"

namespace Roee_ELF {
    #define NUM_ASCII(num) num + '0'

    int elf_perm_to_mmap_perms(u32 const elf_flags);
    s8 memcmp(const void* s1, const void* s2, const u64 n);
    void num_to_str(u64 num, char* buf, u32 digit_len);
}

#endif
