#include "../include/utils.hpp"

namespace Goblin {
bool find_file(const std::filesystem::path &directory, const std::string &filename, std::string &found_path) {
    for (const auto &entry : std::filesystem::recursive_directory_iterator(directory)) {
        if (entry.is_regular_file() && entry.path().filename() == filename) {
            found_path = entry.path().string();
            return true;
        }
    }
    return false;
}

uint32_t get_page_count(const Elf64_Xword memsz, const Elf64_Addr addr) {
    return (memsz + (addr % PAGE_SIZE) + PAGE_SIZE - 1) / PAGE_SIZE;
}

Elf64_Addr page_align_down(const Elf64_Addr addr) { return addr & (~(PAGE_SIZE - 1)); }

unsigned long elf_hash(const unsigned char *name) {
    unsigned long hash = 0;
    unsigned long g;

    while (*name) {
        hash = (hash << 4) + *name++;
        g    = hash & 0xF0000000;
        if (g != 0)
            hash ^= g >> 24;
        hash &= ~g;
    }

    return hash;
}

unsigned long gnu_hash(const unsigned char *name) {
    unsigned long h = 5381;

    for (unsigned char c = *name; c != '\0'; c = *++name) {
        h = (h << 5) + h + c;
    }

    return h;
}
} // namespace Goblin
