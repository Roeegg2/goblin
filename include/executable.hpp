#ifndef GOBLIN_EXECUTABLE_HPP
#define GOBLIN_EXECUTABLE_HPP

#include "loadable.hpp"

#include <elf.h>
#include <queue>

namespace Goblin {
typedef Elf64_Word tid_t;

typedef struct {
    unsigned long int ti_module;
    unsigned long int ti_offset;
} tls_index;

struct tcb {
    void *tp;  // thread pointer (%fs register)
    tid_t tid; // thread id
};

class Executable final : public Loadable {
  private:
	inline void allocate_tid(tid_t &tid);
    void init_thread_static_tls(void);

  public:
    Executable(const std::string file_path, const options_t options);
    ~Executable(void);
    void run(void);

    void *__tls_get_addr(tls_index *ti);

  private:
    std::vector<struct tcb> m_tcbs;
    std::vector<std::vector<void *>> dtvs;
    std::queue<tid_t> m_free_tids; // free thread ids
};
}; // namespace Goblin

#endif
