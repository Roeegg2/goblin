#include "../include/utils.hpp"
#include "../include/syscalls.hpp"

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

    void num_to_str(u64 num, char* buff, u32 digit_num = 0, const u8 base = 10) {
        if (digit_num == 0) { // if number of digits is not specified, calculate it
            digit_num = get_digit_num(num, base);
        }

        for (s32 i = digit_num-1; i >= 0; i--) {
            buff[i] = (num % base) + '0';
            if (buff[i] > 57) {
                buff[i] += 7;
            }

            num /= base;
        }

        // buff[digit_num] = '\0';
    }

    u64 get_digit_num(u64 num, const u8 base = 10) {
        u32 len = 0;
        do {
            num /= base;
            len++;
        } while (num);

        return len;
    }

    void print_str_num(const s32 fd, const u64 num, const u8 base = 10) {
        u64 digit_num = get_digit_num(num, base);
        char buff[digit_num];
        // memset(buff, sizeof(char), digit_num);
        num_to_str(num, buff, digit_num, base);

        switch(base) {
            case 16:
                print_str_literal(fd, "0x");
                break;
            case 10:
                print_str_literal(fd, "0b");
                break;
        }
        syscall_write(fd, buff, digit_num);
    }

    void memset(void *s, const u64 size_of, const u64 n) {
        u64 i = 0;
        while (i < n) {
            for (u8 j = 0; j < size_of; j++) {
                reinterpret_cast<u8*>(s)[i+j] = 0;
            }
            i += size_of;
        }
    }
};
