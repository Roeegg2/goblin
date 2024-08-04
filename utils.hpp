#ifndef UTILS_HPP
#define UTILS_HPP

#include <cstdint>

namespace Roee_ELF {
    int elf_perm_to_mmap_perms(uint32_t const elf_flags);
}

#endif