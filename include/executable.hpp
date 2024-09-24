#ifndef GOBLIN_EXECUTABLE_HPP
#define GOBLIN_EXECUTABLE_HPP

#include "loadable.hpp"

#include <cstdint>
#include <elf.h>
#include <queue>

namespace Goblin {
typedef struct {
    unsigned long int ti_module;
    unsigned long int ti_offset;
} tls_index;

struct tcb {
    void *tp; // thread pointer (%fs register)
    id_t tid; // thread id
};

class Executable final : public Loadable {
  private:
    void allocate_tid(id_t &tid);
    void init_thread_static_tls(void);
    void setup_args_for_start(int exec_argc, char **exec_argv);
    void (*get_main(void))(int, char **, char **);

  public:
    Executable(const std::string file_path, const options_t options);
    ~Executable(void);
    void run(int exec_argc, char **exec_argv);
    void cleanup(void);

    void *__tls_get_addr(tls_index *ti);

  private:
    struct ids tids;
    struct executable_shared m_exec_shared;

    std::vector<struct tcb> m_tcbs;
    std::vector<std::vector<void *>> dtvs;
    struct tls m_tls;

    struct {
        uint16_t strtab;
        uint16_t symtab;
    } m_sect_indices;

    char *m_strtab;
    Elf64_Sym *m_symtab;
};
}; // namespace Goblin

#endif
