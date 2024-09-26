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

extern "C" {
void _GOBLIN_GI(tls_init_tp)(void *tp);
void *_GOBLIN_GI(tls_get_tp)(void);

__attribute((noreturn)) void _GOBLIN_GI(call__start)(int argc, char **argv, void *atexit, void (*_start)(void), uint16_t total_length);
}

namespace Goblin {
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

// looping over the environment variables, getting the last entry
uint16_t Executable::get_env_count(int argc, char **exec_argv) {
    char **env = exec_argv + argc + 1;
    for (; *(env) != NULL; env++) {
        std::cout << *env << std::endl;
    }

    return env - (exec_argv + argc + 1);
}

void Executable::setup_auxv(Elf64_auxv_t *auxv) {
    auxv[AT_NULL].a_un.a_val = 0;                                            // end of vector
    auxv[AT_EXECFD].a_un.a_val = -1;                                         // file descriptor of program
    auxv[AT_PHDR].a_un.a_val = reinterpret_cast<Elf64_Addr>(m_prog_headers); // program headers for
    auxv[AT_PHENT].a_un.a_val = m_elf_header.e_phentsize;                    // size of program header entry
    auxv[AT_PHNUM].a_un.a_val = m_elf_header.e_phnum;                        // number of program headers
    auxv[AT_PAGESZ].a_un.a_val = PAGE_SIZE;                                  // system page size
    auxv[AT_BASE].a_un.a_val = 0;                                            // base address of interpreter
    auxv[AT_FLAGS].a_un.a_val = 0;                                           // flags
    auxv[AT_ENTRY].a_un.a_val = m_elf_header.e_entry + m_load_base_addr;     // entry point of program
    auxv[AT_NOTELF].a_un.a_val = 0;                                          // program is not ELF
    auxv[AT_UID].a_un.a_val = getuid();                                      // real uid
    auxv[AT_EUID].a_un.a_val = geteuid();                                    // effective uid
    auxv[AT_GID].a_un.a_val = getgid();                                      // real gid
    auxv[AT_EGID].a_un.a_val = getegid();                                    // effective gid
    auxv[AT_CLKTCK].a_un.a_val = sysconf(_SC_CLK_TCK);                       // frequency of times()

    // Some more special a_type values describing the hardware.
    auxv[AT_PLATFORM].a_un.a_val = 0; // string identifying platform
    auxv[AT_HWCAP].a_un.a_val = 0;    // machine-dependent hints about processor capabilities

    // This entry gives some information about the FPU initialization
    // performed by the kernel.
    auxv[AT_FPUCW].a_un.a_val = 0; // used FPU control word

    // Cache block sizes.
    auxv[AT_DCACHEBSIZE].a_un.a_val = 0; // data cache block size
    auxv[AT_ICACHEBSIZE].a_un.a_val = 0; // instruction cache block size
    auxv[AT_UCACHEBSIZE].a_un.a_val = 0; // unified cache block size

    // NOTE: remove later on. doing this to skip __tunables_init shit
    auxv[AT_SECURE].a_un.a_val = 0;
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

    const uint16_t total_length = exec_argc + 1 + get_env_count(exec_argc, exec_argv) + 1;
    Elf64_auxv_t *auxv = reinterpret_cast<Elf64_auxv_t *>(exec_argv + total_length - 1);
    setup_auxv(auxv);

    // moving params to _start as specified in start.S
    // asm volatile("movq %0, %%rdi\n\t"
    //              "movl %1, %%esi\n\t"
    //              "movq %2, %%rdx\n\t"
    //              "movq %3, %%rcx\n\t"
    //              "movq %4, %%r8\n\t"
    //              "movq %5, %%r9\n\t"
    //              "pushq %6\n\t"
    //              "jmpq *%7\n\t"
    //              : /* no output */
    //              : "r"(get_main()), "r"(exec_argc), "r"(exec_argv), "r"(NULL), "r"(NULL), "r"(NULL), "r"(NULL), "r"(_GOBLIN__START)
    //              : "rdi", "rsi", "rdx", "rcx", "r8", "r9", "memory");

    _GOBLIN_GI(call__start)(exec_argc, exec_argv, NULL, _GOBLIN__START, total_length);
}
}; // namespace Goblin
