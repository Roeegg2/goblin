#include "../include/utils.hpp"

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

    void num_to_str(u64 num, char* buf, u32 digit_nums = 0) {
        if (digit_nums == 0) { // if number of digits is not specified, calculate it
            u32 temp = num;
            while (temp) {
                temp /= 10;
                digit_nums++;
            }
        }

        for (s32 i = digit_nums-1; i >= 0; i--) {
            buf[i] = (num % 10) + '0';
            num /= 10;
        }

        buf[digit_nums] = '\0';
    }
};
