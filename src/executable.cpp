#include "../include/executable.hpp"

#include "../include/_gnu_auxv.hpp"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <iostream>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

/*prefix Goblin internal assembly functions (to avoid naming collision with
 * other libraries and stuff)*/
#define _GOBLIN_GI(sym) _goblin_##sym
#define _GOBLIN__START (reinterpret_cast<void (*)(void)>(m_load_base_addr + m_elf_header.e_entry))
#define _GOBLIN_SET_AUXV_ENT(type, value)                                                                                                  \
    auxv[type].a_un.a_val = value;                                                                                                         \
    auxv[type].a_type = type;

extern "C" {
__attribute__((noreturn)) void _GOBLIN_GI(call__start)(int argc, char **argv, void *atexit, void (*_start)(void), uint16_t total_length);
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

void Executable::setup_auxv(Elf64_auxv_t *auxv) {
    _GOBLIN_SET_AUXV_ENT(AT_NULL, 0xdeadbeef);
    _GOBLIN_SET_AUXV_ENT(AT_IGNORE, 0);
    _GOBLIN_SET_AUXV_ENT(AT_EXECFD, open("tests/libctest", O_RDONLY)); // FIXME: this is ugly as hgell
    _GOBLIN_SET_AUXV_ENT(AT_PHDR, reinterpret_cast<Elf64_Addr>(m_prog_headers));
    _GOBLIN_SET_AUXV_ENT(AT_PHENT, m_elf_header.e_phentsize);
    _GOBLIN_SET_AUXV_ENT(AT_PHNUM, m_elf_header.e_phnum);
    _GOBLIN_SET_AUXV_ENT(AT_PAGESZ, PAGE_SIZE);
    _GOBLIN_SET_AUXV_ENT(AT_BASE, 0);
    _GOBLIN_SET_AUXV_ENT(AT_FLAGS, 0);
    _GOBLIN_SET_AUXV_ENT(AT_ENTRY, m_elf_header.e_entry + m_load_base_addr);
    _GOBLIN_SET_AUXV_ENT(AT_NOTELF, 0);
    _GOBLIN_SET_AUXV_ENT(AT_UID, getuid());
    _GOBLIN_SET_AUXV_ENT(AT_EUID, geteuid());
    _GOBLIN_SET_AUXV_ENT(AT_GID, getgid());
    _GOBLIN_SET_AUXV_ENT(AT_EGID, getegid());
    _GOBLIN_SET_AUXV_ENT(AT_CLKTCK, sysconf(_SC_CLK_TCK));
    _GOBLIN_SET_AUXV_ENT(AT_PLATFORM, 0);
    _GOBLIN_SET_AUXV_ENT(AT_HWCAP, 0);
    _GOBLIN_SET_AUXV_ENT(AT_SECURE, 1);
    _GOBLIN_SET_AUXV_ENT(AT_RANDOM, reinterpret_cast<Elf64_Addr>(&_dl_random));
}

void Executable::run(int exec_argc, char **exec_argv) {
    build_shared_objs_tree(m_exec_shared);

#ifdef DEBUG
    if (m_dyn_seg_index > 0) {
        print_dynamic_segment();
    }
#endif
    cleanup();
    // FIXME: get rid of not used anymore stuff
    {

        char **env = exec_argv + exec_argc + 1;
        for (; *(env) != NULL; env++) {
            // std::cout << *env << std::endl;
        }

        auto env_count = env - (exec_argv + exec_argc + 1);
        Elf64_auxv_t *auxv = reinterpret_cast<Elf64_auxv_t *>(env + env_count + 1);
        setup_auxv(auxv);

        // doing it here, since doing it before messes up with glibc
        // _GOBLIN_GI(tls_init_tp)(tp); // set the thread pointer to point to the tcb
        _GOBLIN_GI(call__start)(exec_argc, exec_argv, NULL, _GOBLIN__START, exec_argc + 1 + env_count + 1 + AT_MINSIGSTKSZ + 1);
    }
}
}; // namespace Goblin
