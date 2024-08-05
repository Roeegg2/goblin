#ifndef UTILS_HPP
#define UTILS_HPP

#include "types.hpp"

namespace Roee_ELF {
    int elf_perm_to_mmap_perms(u32 const elf_flags);
    s8 memcmp(const void* s1, const void* s2, const u64 n);
}

#endif