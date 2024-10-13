#ifndef GOBLIN_EXECUTABLE_HPP
#define GOBLIN_EXECUTABLE_HPP

#include "_gnu_tls.hpp"
#include "loadable.hpp"

#include <cstdint>
#include <elf.h>

namespace Goblin {
class Executable final : public Loadable {
  private:
    id_t init_tcb(void *tp);
    void allocate_dtv(const id_t tid);
    void *init_thread_static_tls(void);
    void setup_args_for_start(int exec_argc, char **exec_argv);
    uint16_t get_env_count(int argc, char **exec_argv);
    void setup_auxv(Elf64_auxv_t *auxv);
    void (*get_main(void))(int, char **, char **);
    uint8_t init_auxv(Elf64_auxv_t *new_auxv, Elf64_auxv_t *old_auxv);

  public:
    Executable(const std::string file_path, const options_t options);
    ~Executable(void);
    void run(int exec_argc, char **exec_argv, char **exec_envp);
    void cleanup(void);

    void *__tls_get_addr(tls_index *ti);

  private:
    struct executable_shared m_exec_shared;

    std::vector<tcbhead_t *> m_tcbs;

    struct {
        uint16_t strtab;
        uint16_t symtab;
    } m_sect_indices;

    char *m_strtab;
    Elf64_Sym *m_symtab;
};
}; // namespace Goblin

#endif
