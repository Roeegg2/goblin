#ifndef UTILS_HPP
#define UTILS_HPP

#include <stdint.h>

namespace Roee_ELF {
#define STR_LITERAL_LEN(buff) ((sizeof(buff) / sizeof(char))-1)
#define NULL 0x0

    int elf_perm_to_mmap_perms(uint32_t const elf_flags);
    int8_t memcmp(const void* s1, const void* s2, const uint64_t n);
    void memset(void *s, const uint8_t val, const uint64_t n);
    void num_to_str(uint64_t num, char* buff, uint32_t digit_num = 0, const uint8_t base = 10);
    uint64_t get_digit_num(uint64_t num, const uint8_t base = 10);

#define print_str_literal(fd, buff) (syscall_write(fd, buff, STR_LITERAL_LEN(buff)))
    void print_str_num(const int32_t fd, const uint64_t num, const uint8_t base = 10);
}

#endif
