#ifndef UTILS_HPP
#define UTILS_HPP

#include <cstdint>
#include <cstring>
#include <elf.h>
#include <stdint.h>

namespace Roee_ELF {
    constexpr uint16_t PAGE_SIZE = 0x1000;
#define PAGE_ALIGN_DOWN(addr) ((addr) & ~(PAGE_SIZE-1))

    int elf_perm_to_mmap_perms(uint32_t const elf_flags);
}

#endif
