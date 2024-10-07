#ifndef GOBLIN_UTILS_HPP
#define GOBLIN_UTILS_HPP

#include <elf.h>
#include <filesystem>
#include <queue>
#include <string>

// TODO: change these to std::cerr, and figure out the issue
#define _GOBLIN_PRINT_WARN(msg) std::cout << "[WARNING] " << msg << "\n";
#define _GOBLIN_PRINT_INFO(msg) std::cout << "[INFO] " << msg << std::endl;
#define _GOBLIN_PRINT_ERR(msg)                                                                                                             \
    std::cout << "[ERROR] " << msg << "\n";                                                                                                \
    exit(1);
#define _GOBLIN_PRINT_ERR_INTERNAL(msg)                                                                                                    \
    std::cout << "[INTERNAL ERROR] " << msg << "\n";                                                                                       \
    exit(1);

namespace Goblin {
typedef Elf64_Word id_t;

constexpr uint16_t PAGE_SIZE = 0x1000;

class IDs {
  public:
    id_t allocate_id();
    inline void free_id(const id_t id);

  private:
    std::queue<id_t> m_free_ids;
    id_t m_biggest_allocated;
};

bool find_file(const std::filesystem::path &directory, const std::string &filename, std::string &found_path);
uint32_t get_page_count(const Elf64_Xword memsz, const Elf64_Addr addr);
Elf64_Addr page_align_down(const Elf64_Addr addr);
unsigned long elf_hash(const unsigned char *name);
uint32_t gnu_hash(const uint8_t *name);
int elf_perm_to_mmap_perms(const uint32_t elf_flags);

// unsigned long gnu_hash(const unsigned char *name);
}; // namespace Goblin

#endif
