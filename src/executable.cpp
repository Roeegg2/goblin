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
__attribute__((noreturn)) void _GOBLIN_GI(call__start)(void *argv_end, void (*_start)(void), int argc);
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
void Executable::run(int exec_argc, char **exec_argv, char **exec_envp) {
    build_shared_objs_tree(m_exec_shared);

#ifdef DEBUG
    if (m_dyn_seg_index > 0) {
        print_dynamic_segment();
    }
#endif
    cleanup();
    // FIXME: get rid of not used anymore stuff

    uint16_t envp_cnt = 0;
    for (; exec_envp[envp_cnt] != AT_NULL; envp_cnt++)
        ;
    // we push:
    // ------- STACK BOTTOM -----------
    // env strings, argv strings, some padding, other shit linux loader already put we don't need to worry about
    // auxv[n] (AT_NULL) NOTE: you can just push only the a_type to save 8 bytes of space, but fuck that
    // auxv[n-1]
    // ...
    // auxv[0]
    // NULL
    // envp[n]
    // envp[n-1]
    // ...
    // envp[0]
    // NULL
    // argv[n]
    // argv[n-1]
    // ...
    // argv[0]
    // argc

    // NOTE: auxv 99.99% won't _actually_ be AT_MINSIGSTKSZ + 1, but this is the maximum possible length
    const auto total_length =
        1 + (exec_argc * sizeof(char *)) + 1 + (envp_cnt * sizeof(char *)) + 1 + (sizeof(Elf64_auxv_t) * (AT_MINSIGSTKSZ + 1));
    void *new_argv = (void *)(std::malloc(total_length));

    char **foo_argv = reinterpret_cast<char **>(new_argv);
    uint8_t i = 0;
    for (; i < exec_argc; i++) {
        foo_argv[i] = exec_argv[i];
    }
    foo_argv[i] = NULL;
    for (i++; i < exec_argc + 1 + envp_cnt; i++) {
        foo_argv[i] = exec_argv[i];
    }
    foo_argv[i] = NULL;

    Elf64_auxv_t *end_auxv = reinterpret_cast<Elf64_auxv_t *>(foo_argv + i + 1);
    {
#define _GOBLIN_SET_AUXV_ENT(type, value)                                                                                                  \
    end_auxv->a_un.a_val = value;                                                                                                          \
    end_auxv->a_type = type;                                                                                                               \
    end_auxv++;

        _GOBLIN_SET_AUXV_ENT(AT_SYSINFO_EHDR, 0);
        _GOBLIN_SET_AUXV_ENT(AT_MINSIGSTKSZ, 0);
        _GOBLIN_SET_AUXV_ENT(AT_HWCAP, 0);
        _GOBLIN_SET_AUXV_ENT(AT_PAGESZ, 0);
        {
            char *phdr = new char[m_elf_header.e_phentsize * m_elf_header.e_phnum];
            m_elf_file.seekg(m_elf_header.e_phoff);
            m_elf_file.read(phdr, m_elf_header.e_phentsize * m_elf_header.e_phnum);
            _GOBLIN_SET_AUXV_ENT(AT_PHDR, reinterpret_cast<uint64_t>(phdr));
        }
        _GOBLIN_SET_AUXV_ENT(AT_PHENT, m_elf_header.e_phentsize);
        _GOBLIN_SET_AUXV_ENT(AT_PHNUM, m_elf_header.e_phnum);
        _GOBLIN_SET_AUXV_ENT(AT_BASE, m_load_base_addr);
        _GOBLIN_SET_AUXV_ENT(AT_FLAGS, 0);
        _GOBLIN_SET_AUXV_ENT(AT_ENTRY, m_elf_header.e_entry);
        _GOBLIN_SET_AUXV_ENT(AT_UID, 0);
        _GOBLIN_SET_AUXV_ENT(AT_EUID, 0);
        _GOBLIN_SET_AUXV_ENT(AT_GID, 0);
        _GOBLIN_SET_AUXV_ENT(AT_EGID, 0);
        _GOBLIN_SET_AUXV_ENT(AT_SECURE, 0);
        // if not provided by the kernel
        _GOBLIN_SET_AUXV_ENT(AT_RANDOM, 0);
        // _GOBLIN_SET_AUXV_ENT(AT_HWCAP2, 0);
        _GOBLIN_SET_AUXV_ENT(AT_EXECFN, 0);
        _GOBLIN_SET_AUXV_ENT(AT_PLATFORM, 0);
        _GOBLIN_SET_AUXV_ENT(AT_RSEQ_FEATURE_SIZE, 0);
        _GOBLIN_SET_AUXV_ENT(AT_RSEQ_ALIGN, 0);
        _GOBLIN_SET_AUXV_ENT(AT_NULL, 0);
#undef _GOBLIN_SET_AUXV_ENT
    }
    {
        Elf64_auxv_t *foo_auxv = reinterpret_cast<Elf64_auxv_t *>(foo_argv + i + 1);
        for (; foo_auxv->a_type != AT_NULL; foo_auxv++) {
            for (auto old_auxv = reinterpret_cast<Elf64_auxv_t *>(exec_envp + envp_cnt + 1); old_auxv->a_type != AT_NULL; old_auxv++) {
                if ((foo_auxv->a_type == old_auxv->a_type) && (foo_auxv->a_un.a_val == 0)) {
                    foo_auxv->a_un.a_val = old_auxv->a_un.a_val;
                }
            }
        }
    }
    // print envp:
    for (uint16_t i = 0; i < envp_cnt; i++) {
        std::cout << "envp[" << i << "]: " << exec_envp[i] << std::endl;
    }
    // print argv:
    for (uint16_t i = 0; i < exec_argc; i++) {
        std::cout << "argv[" << i << "]: " << exec_argv[i] << std::endl;
    }

    for (Elf64_auxv_t *foo_auxv = reinterpret_cast<Elf64_auxv_t *>(foo_argv + i + 1);
         reinterpret_cast<Elf64_auxv_t *>(foo_auxv) <= end_auxv; foo_auxv++) {
        std::cout << std::dec << "type: " << reinterpret_cast<Elf64_auxv_t *>(foo_auxv)->a_type << std::hex
                  << " value: " << reinterpret_cast<Elf64_auxv_t *>(foo_auxv)->a_un.a_val << std::endl;
    }

    _GOBLIN_GI(call__start)(reinterpret_cast<void *>(end_auxv - 1), _GOBLIN__START, exec_argc);
}
}; // namespace Goblin
