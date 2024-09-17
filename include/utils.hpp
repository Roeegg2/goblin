#ifndef GOBLIN_UTILS_HPP
#define GOBLIN_UTILS_HPP

#include <elf.h>
#include <filesystem>
#include <string>

namespace Goblin {
constexpr uint16_t PAGE_SIZE = 0x1000;

bool find_file(const std::filesystem::path &directory, const std::string &filename, std::string &found_path);
uint32_t get_page_count(const Elf64_Xword memsz, const Elf64_Addr addr);
Elf64_Addr page_align_down(const Elf64_Addr addr);
}; // namespace Goblin

#endif
