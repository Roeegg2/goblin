#include "../include/executable.hpp"

#include "../include/_gnu_auxv.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <iostream>
#include <sys/mman.h>
#include <unistd.h>

/*prefix Goblin internal assembly functions (to avoid naming collision with
 * other libraries and stuff)*/
#define _GOBLIN_GI(sym) _goblin_##sym
#define _GOBLIN__START (reinterpret_cast<void (*)(void)>(m_load_base_addr + m_elf_header.e_entry))

extern "C" {
__attribute__((noreturn)) void _GOBLIN_GI(call__start)(char **argv, char **envp, Elf64_auxv_t *auxv, int argc,
                                                       __attribute__((noreturn)) void (*_start)(void), uint16_t envp_cnt);
}

namespace Goblin {

uint64_t _dl_random = 0xabcdabcd;

Executable::Executable(const std::string file_path, const options_t options) : Loadable(file_path) {
    // get section table indices
    m_sect_indices.strtab = get_section_index_by_name(".strtab");
    m_sect_indices.symtab = get_section_index_by_name(".symtab");

    // copy the data of the sections to buffers, to be used later

    m_strtab = new char[m_sect_headers[m_sect_indices.strtab].sh_size];
    m_elf_file.seekg(m_sect_headers[m_sect_indices.strtab].sh_offset);
    m_elf_file.read(m_strtab, m_sect_headers[m_sect_indices.strtab].sh_size);

    m_symtab = new Elf64_Sym[m_sect_headers[m_sect_indices.symtab].sh_size / sizeof(Elf64_Sym)];
    m_elf_file.seekg(m_sect_headers[m_sect_indices.symtab].sh_offset);
    m_elf_file.read(reinterpret_cast<char *>(m_symtab), m_sect_headers[m_sect_indices.symtab].sh_size);

    m_exec_shared.m_options = options;
}

Executable::~Executable(void) {}

void Executable::cleanup() { return; }

void (*Executable::get_main(void))(int, char **, char **) {
    Elf64_Sym *main_sym = get_sym_by_name(
        m_symtab, m_strtab, "main", (m_sect_headers[m_sect_indices.symtab].sh_size / m_sect_headers[m_sect_indices.symtab].sh_entsize));

    if (main_sym == nullptr) {
        _GOBLIN_PRINT_WARN("Couldn't find \'main\' function. This should be concerning if program is using glibc\n");
        return nullptr;
    }

    return reinterpret_cast<void (*)(int, char **, char **)>(main_sym->st_value + m_load_base_addr);
}

uint8_t Executable::init_auxv(Elf64_auxv_t *new_auxv, Elf64_auxv_t *old_auxv) {
    // ORDER OF AUXV ENTRIES:
    // 1. (if vdso enabled) AT_SYSINFO_EHDR
    // 2. AT_MINSIGSTKSZ
    //
    // 3. AT_HWCAP
    // 4. AT_PAGESZ
    // 5. AT_PHDR
    // 6. AT_PHENT
    // 7. AT_PHNUM
    // 8. AT_BASE
    // 9. AT_FLAGS
    // 10. AT_ENTRY
    // 11. AT_UID
    // 12. AT_EUID
    // 13. AT_GID
    // 14. AT_EGID
    // 15. AT_SECURE
    // 16. AT_RANDOM
    //
    // 17. AT_HWCAP2
    // 18. AT_EXECFN
    // 19. AT_PLATFORM
    // 20. AT_RSEQ_FEATURE_SIZE
    // 21. AT_RSEQ_ALIGN
    // 22. AT_NULL

    // copy values from Goblin's auxv to new auxv
    uint8_t i = 0;
#define _GOBLIN_SET_AUXV_ENT(i, type, value)                                                                                               \
    new_auxv[i].a_un.a_val = value;                                                                                                        \
    new_auxv[i].a_type = type;                                                                                                             \
    i++;
    // if vdso enabled
    _GOBLIN_SET_AUXV_ENT(i, AT_SYSINFO_EHDR, 0);
    _GOBLIN_SET_AUXV_ENT(i, AT_MINSIGSTKSZ, 0);
    _GOBLIN_SET_AUXV_ENT(i, AT_HWCAP, 0);
    _GOBLIN_SET_AUXV_ENT(i, AT_PAGESZ, 0);
    {
        char *phdr = new char[m_elf_header.e_phentsize * m_elf_header.e_phnum];
        m_elf_file.seekg(m_elf_header.e_phoff);
        m_elf_file.read(phdr, m_elf_header.e_phentsize * m_elf_header.e_phnum);
        _GOBLIN_SET_AUXV_ENT(i, AT_PHDR, reinterpret_cast<uint64_t>(phdr));
    }
    _GOBLIN_SET_AUXV_ENT(i, AT_PHENT, m_elf_header.e_phentsize);
    _GOBLIN_SET_AUXV_ENT(i, AT_PHNUM, m_elf_header.e_phnum);
    _GOBLIN_SET_AUXV_ENT(i, AT_BASE, m_load_base_addr);
    _GOBLIN_SET_AUXV_ENT(i, AT_FLAGS, 0);
    _GOBLIN_SET_AUXV_ENT(i, AT_ENTRY, m_elf_header.e_entry);
    _GOBLIN_SET_AUXV_ENT(i, AT_UID, 0);
    _GOBLIN_SET_AUXV_ENT(i, AT_EUID, 0);
    _GOBLIN_SET_AUXV_ENT(i, AT_GID, 0);
    _GOBLIN_SET_AUXV_ENT(i, AT_EGID, 0);
    _GOBLIN_SET_AUXV_ENT(i, AT_SECURE, 0);
    // if not provided by the kernel
    _GOBLIN_SET_AUXV_ENT(i, AT_RANDOM, reinterpret_cast<uint64_t>(&_dl_random));
    _GOBLIN_SET_AUXV_ENT(i, AT_HWCAP2, 0);
    _GOBLIN_SET_AUXV_ENT(i, AT_EXECFN, 0);
    _GOBLIN_SET_AUXV_ENT(i, AT_PLATFORM, 0);
    _GOBLIN_SET_AUXV_ENT(i, AT_RSEQ_FEATURE_SIZE, 0);
    _GOBLIN_SET_AUXV_ENT(i, AT_RSEQ_ALIGN, 0);
    _GOBLIN_SET_AUXV_ENT(i, AT_NULL, 0);
#undef _GOBLIN_SET_AUXV_ENT

    // ugly and inefficient but i dont give a fuck
    for (uint8_t j = 0; j < 22; j++) {
        for (auto foo_auxv = old_auxv; foo_auxv->a_type != AT_NULL; foo_auxv++) {
            if ((new_auxv[j].a_type == foo_auxv->a_type) && (new_auxv[j].a_un.a_val == 0)) {
                new_auxv[j].a_un.a_val = foo_auxv->a_un.a_val;
            }
        }
    }

    return i;
}

void Executable::run(int exec_argc, char **exec_argv, char **exec_envp) {
    build_shared_objs_tree(m_exec_shared);

#ifdef DEBUG
    if (m_dyn_seg_index > 0) {
        print_dynamic_segment();
    }
#endif
    cleanup();
    // FIXME: get rid of not used anymore stuff

    uint16_t envp_cnt;
    Elf64_auxv_t *new_auxv = new Elf64_auxv_t[AT_MINSIGSTKSZ + 1];
    {

        // get old auxv
        Elf64_auxv_t *old_auxv;
        for (envp_cnt = 0; exec_envp[envp_cnt] != AT_NULL; envp_cnt++)
            ;
        std::cout << "envp_cnt: " << envp_cnt << std::endl;
        old_auxv = reinterpret_cast<Elf64_auxv_t *>(exec_envp + envp_cnt + 1);

        // init new auxv
        uint8_t auxv_cnt = init_auxv(new_auxv, old_auxv);

        for (auto i = 0; i <= auxv_cnt; i++) {
            std::cout << std::dec << "type: " << new_auxv[i].a_type << std::hex << " value: " << new_auxv[i].a_un.a_val << std::endl;
        }

        _GOBLIN_GI(call__start)
        (exec_argv + exec_argc - 1, exec_envp + envp_cnt - 1, new_auxv + auxv_cnt - 1, exec_argc, _GOBLIN__START, envp_cnt);
    }
}
}; // namespace Goblin
