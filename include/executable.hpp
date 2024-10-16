#ifndef GOBLIN_EXECUTABLE_HPP
#define GOBLIN_EXECUTABLE_HPP

#include "_gnu_tls.hpp"
#include "loadable.hpp"

#include <cstdint>
#include <elf.h>

namespace Goblin {
class Executable final : public Loadable {
  private:
    __attribute__((always_inline)) inline void push_auxv_entries(const Elf64_auxv_t *auxv);
    void init_tls(void);
    void cleanup(void);

  public:
    Executable(const std::string file_path, const options_t options);
    ~Executable(void);
    __attribute__((noreturn)) void run(int exec_argc, char **exec_argv, char **exec_envp);

    void *__tls_get_addr(tls_index *ti);

  private:
    struct executable_shared m_exec_shared;

    std::vector<tcbhead_t *> m_tcbs;
    IDs m_tids;

    struct {
        uint16_t strtab;
        uint16_t symtab;
    } m_sect_indices;

    char *m_strtab;
    Elf64_Sym *m_symtab;
};
}; // namespace Goblin

#endif
