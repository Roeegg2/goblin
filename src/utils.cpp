#include "../include/utils.hpp"
#include "../include/syscalls.hpp"

#include <cstdint>
#include <sys/mman.h>

namespace Roee_ELF {
    int elf_perm_to_mmap_perms(uint32_t const elf_flags) {
        int mmap_flags = 0;

        if (elf_flags & 0x1) mmap_flags |= PROT_EXEC;
        if (elf_flags & 0x2) mmap_flags |= PROT_WRITE;
        if (elf_flags & 0x4) mmap_flags |= PROT_READ;

        return mmap_flags;
    }

    int8_t memcmp(const void* s1, const void* s2, const uint64_t n) {
        for (uint64_t i = 0; i < n; i++) {
            if (((uint8_t*)s1)[i] != ((uint8_t*)s2)[i]) {
                return ((uint8_t*)s1)[i] - ((uint8_t*)s2)[i];
            }
        }

        return 0;
    }

    void num_to_str(uint64_t num, char* buff, uint32_t digit_num, const uint8_t base) {
        if (digit_num == 0) { // if number of digits is not specified, calculate it
            digit_num = get_digit_num(num, base);
        }

        for (int32_t i = digit_num-1; i >= 0; i--) {
            buff[i] = (num % base) + '0';
            if (buff[i] > 57) {
                buff[i] += 7;
            }

            num /= base;
        }

        // buff[digit_num] = '\0';
    }

    uint64_t get_digit_num(uint64_t num, const uint8_t base) {
        uint32_t len = 0;
        do {
            num /= base;
            len++;
        } while (num);

        return len;
    }

    void print_str_num(const int32_t fd, const uint64_t num, const uint8_t base) {
        uint64_t digit_num = get_digit_num(num, base);
        char* buff = reinterpret_cast<char*>(syscall_mmap(NULL, digit_num, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
        // memset(buff, sizeof(char), digit_num);
        num_to_str(num, buff, digit_num, base);

        switch(base) {
            case 16:
                print_str_literal(fd, "0x");
                break;
            case 2:
                print_str_literal(fd, "0b");
                break;
        }
        syscall_write(fd, buff, digit_num);

        syscall_munmap(reinterpret_cast<uint64_t>(buff), digit_num);
    }

    void memset(void *s, const uint8_t val, const uint64_t n) {
        uint64_t i = 0;
        while (i < n) {
            reinterpret_cast<uint8_t*>(s)[i] = val;
            i++;
        }
    }

    void memcpy(void* s1, void* s2, const uint64_t n) {
        for (uint64_t i = 0; i < n; i++) {
            reinterpret_cast<uint8_t*>(s1)[i] = reinterpret_cast<uint8_t*>(s2)[i];
        }
    }

    void mmap_wrapper(void** ptr, Elf64_Addr addr, Elf64_Xword size, uint64_t prot, uint64_t flags,
        uint64_t fd, Elf64_Off offset) {
        *ptr = reinterpret_cast<void*>(syscall_mmap(addr, size,
            prot, flags, fd, PAGE_ALIGN_DOWN(offset)));

        if (*ptr == MAP_FAILED) {
            print_str_literal(STDOUT_FD, "mmap failed\n");
            syscall_exit(1);
        }
    }
};
