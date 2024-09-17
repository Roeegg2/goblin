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
} // namespace Goblin
