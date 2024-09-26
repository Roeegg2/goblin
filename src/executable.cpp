#include "../include/executable.hpp"

#include "../include/_gnu_auxv.hpp"

#include <cstdint>
#include <cstring>
#include <elf.h>
#include <iostream>
#include <sys/mman.h>
#include <unistd.h>

/*prefix Goblin internal assembly functions (to avoid naming collision with
 * other libraries and stuff)*/
#define _GOBLIN_GI(sym) _goblin_##sym
#define _GOBLIN__START (reinterpret_cast<void (*)(void)>(m_load_base_addr + m_elf_header.e_entry))
#define _GOBLIN_SET_AUXV_ENT(type, value)                                                                                                  \
    auxv[type].a_un.a_val = value;                                                                                                         \
    auxv[type].a_type = type;

extern "C" {
void _GOBLIN_GI(tls_init_tp)(void *tp);
void *_GOBLIN_GI(tls_get_tp)(void);

__attribute__((noreturn)) void _GOBLIN_GI(call__start)(int argc, char **argv, void *atexit, void (*_start)(void), uint16_t total_length);
}

namespace Goblin {

uint64_t _dl_random = 0xabcdabcd;

Executable::Executable(const std::string file_path, const options_t options) : Loadable(file_path, options) {
    m_sect_indices.strtab = get_section_index_by_name(".strtab");
    m_sect_indices.symtab = get_section_index_by_name(".symtab");

    m_strtab = new char[m_sect_headers[m_sect_indices.strtab].sh_size];
    m_elf_file.seekg(m_sect_headers[m_sect_indices.strtab].sh_offset);
    m_elf_file.read(m_strtab, m_sect_headers[m_sect_indices.strtab].sh_size);

    m_symtab = new Elf64_Sym[m_sect_headers[m_sect_indices.symtab].sh_size / sizeof(Elf64_Sym)];
    m_elf_file.seekg(m_sect_headers[m_sect_indices.symtab].sh_offset);
    m_elf_file.read(reinterpret_cast<char *>(m_symtab), m_sect_headers[m_sect_indices.symtab].sh_size);
}

Executable::~Executable(void) {}

void *Executable::__tls_get_addr(tls_index *ti) {
    const id_t tid = reinterpret_cast<struct tcb *>(_goblin_tls_get_tp())->tid;
    if (ti->ti_module > dtvs[tid].size()) { // first case no block is allocated - when module id
                                            // is greater than the number of tls blocks allocated
        goto allocate_new;
    }

    {
        void *tls_block = dtvs[tid][ti->ti_module - 1]; // we start couting modules from 1
        if (tls_block == nullptr) {                     // second case no block is allocated - when it was used
                                                        // before, but the module it belonged to was unloaded
            goto allocate_new;
            /*not handling this yet... we will worry about dlopen loaded modules
             * later.. :)*/
        }
        return reinterpret_cast<void *>(reinterpret_cast<Elf64_Addr>(tls_block) + ti->ti_offset);
    }

allocate_new:
    dtvs[tid].resize(ti->ti_module);
    dtvs[tid][ti->ti_module - 1] = mmap(nullptr, m_tls.m_total_imgs_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    std::memcpy(dtvs[tid][ti->ti_module - 1], m_tls.m_init_imgs[ti->ti_module - 1].m_data, m_tls.m_init_imgs[ti->ti_module - 1].m_size);

    return reinterpret_cast<void *>(reinterpret_cast<Elf64_Addr>(dtvs[tid][ti->ti_module - 1]) + ti->ti_offset);
}

/*code here might cause some confusion. TP here (thread pointer) is point on its
 * right to the TCB, and on the left to the TLS blocks. so in the code its used
 * sometimes for this and sometimes for that*/

void Executable::init_thread_static_tls() {
    // allocate memory for the tls blocks and tcb, as specified in variant 2
    void *tp = mmap(nullptr, m_tls.m_total_imgs_size + sizeof(struct tcb), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    tp = reinterpret_cast<void *>(reinterpret_cast<Elf64_Addr>(tp) + m_tls.m_total_imgs_size);
    _GOBLIN_GI(tls_init_tp)(tp); // set the thread pointer to point to the tcb

    /*FIXME: improve this mechanism*/
    reinterpret_cast<struct tcb *>(tp)->tp = tp;                 // make TCP point to self
    reinterpret_cast<struct tcb *>(tp)->tid = allocate_id(tids); // allocate a new tid

    tp = reinterpret_cast<void *>(reinterpret_cast<Elf64_Addr>(tp) - m_tls.m_total_imgs_size);
    for (auto &img : m_tls.m_init_imgs) {
        if (img.m_is_static_model) {

            std::memcpy(tp, img.m_data, img.m_size);                         // copy the TLS block image to the TLS block
            dtvs[reinterpret_cast<struct tcb *>(tp)->tid - 1].push_back(tp); // NOTE: we initlized the m_init_imgs vector the same order we
                                                                             // would've assigned module ids so we can just push_back and
                                                                             // not have to worry about the order
            tp = reinterpret_cast<void *>(reinterpret_cast<Elf64_Addr>(tp) + img.m_size);
        }
    }
}

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
    _GOBLIN_SET_AUXV_ENT(AT_EXECFD, -1);
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

    std::cout << "_dl_random address is: " << &_dl_random << std::endl;
}

void Executable::run(int exec_argc, char **exec_argv) {
    build_shared_objs_tree(m_exec_shared);
    init_thread_static_tls();

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

        _GOBLIN_GI(call__start)(exec_argc, exec_argv, NULL, _GOBLIN__START, exec_argc + 1 + env_count + 1 + AT_MINSIGSTKSZ + 1);
    }
}
}; // namespace Goblin
