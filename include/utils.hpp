#ifndef GOBLIN_UTILS_HPP
#define GOBLIN_UTILS_HPP

#include <elf.h>
#include <queue>

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

constexpr const uint64_t MAGIC = 0x746F6C6564616E6F;
constexpr uint16_t PAGE_SIZE = 0x1000;

class IDs {
  public:
    id_t allocate_id(void);
    inline void free_id(const id_t id);

  private:
    std::queue<id_t> m_free_ids;
    id_t m_biggest_allocated;
};

}; // namespace Goblin

#endif
