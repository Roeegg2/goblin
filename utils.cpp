#include "utils.hpp"

#include <sys/mman.h>

namespace Roee_ELF {
    int elf_perm_to_mmap_perms(u32 const elf_flags) {
        int mmap_flags = 0;

        if (elf_flags & 0x1) mmap_flags |= PROT_EXEC;
        if (elf_flags & 0x2) mmap_flags |= PROT_WRITE;
        if (elf_flags & 0x4) mmap_flags |= PROT_READ;

        return mmap_flags;
    }

    s8 memcmp(const void* s1, const void* s2, const u64 n) {
        for (u64 i = 0; i < n; i++) {
            if (((u8*)s1)[i] != ((u8*)s2)[i]) {
                return ((u8*)s1)[i] - ((u8*)s2)[i];
            }
        }

        return 0;
    }
};