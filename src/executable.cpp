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

/*prefix Goblin internal assembly functions (to avoid naming collision with
 * other libraries and stuff)*/
#define _GOBLIN_GI(sym) _goblin_##sym

extern "C" {
__attribute__((noreturn)) void _GOBLIN_GI(atexit)(void);
uint64_t _GOBLIN_GI(set_tp)(void *tp);
uint64_t _GOBLIN_GI(get_tp)(void);
}

namespace Goblin {

uint32_t get_page_count(const Elf64_Xword memsz, const Elf64_Addr addr);

Executable::Executable(const std::string file_path, const options_t options) : Loadable(file_path) { m_exec_shared.m_options = options; }

void Executable::init_tls(void) {
    // allocate memory for the TLS (TCB + TLS blocks)
    void *blocks_end = mmap(NULL, get_page_count(m_exec_shared.m_tls.m_total_imgs_size + sizeof(tcbhead_t), 0), PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (blocks_end == MAP_FAILED) {
        _GOBLIN_PRINT_ERR_INTERNAL("mmap failed allocating memory for TLS");
    }

    // set the TCB
    tcbhead_t *tcb = reinterpret_cast<tcbhead_t *>(reinterpret_cast<Elf64_Addr>(blocks_end) + m_exec_shared.m_tls.m_total_imgs_size);
    // _GOBLIN_GI(set_tp)(tcb);
    tcb->tcb = tcb;
    tcb->self = tcb;
    tcb->dtv = new dtv_t[m_exec_shared.m_tls.m_init_imgs.size()];
    // set tid
    id_t tid = m_tids.allocate_id();
    if (tid >= m_tcbs.size()) {
        m_tcbs.resize(tid + 1);
    }
    m_tcbs[tid] = tcb;

    // initialize TLS blocks for this thread
    for (int i = m_exec_shared.m_tls.m_init_imgs.size() - 1; i >= 0; i--) {
        // copy data from initialization image to the TLS block
        std::memcpy(blocks_end, m_exec_shared.m_tls.m_init_imgs[i].m_data, m_exec_shared.m_tls.m_init_imgs[i].m_size);
        // set DTV entry for this TLS block
        tcb->dtv[i].pointer.val = blocks_end;
        tcb->dtv[i].pointer.to_free = nullptr;
        // move the pointer to the next TLS block
        blocks_end = reinterpret_cast<void *>(reinterpret_cast<uint64_t>(blocks_end) + m_exec_shared.m_tls.m_init_imgs[i].m_size);
    }
}

static uint64_t get_org_auxv_entry(const Elf64_auxv_t *auxv, const uint64_t type) {
    for (; auxv->a_type != AT_NULL; auxv++) {
        if (auxv->a_type == type) {
            return auxv->a_un.a_val;
        }
    }

    return MAGIC;
}

__attribute__((always_inline)) static inline void push_argv_envp_entries(int i, char **exec) {
    for (i--; i >= 0; i--) {
        asm volatile("pushq %0\n\t" : : "r"((uint64_t)exec[i]) : "memory");
    }
}

__attribute__((always_inline)) inline void Executable::push_auxv_entries(const Elf64_auxv_t *auxv) {

#define _GOBLIN_SET_AUXV_ENT(type, value)                                                                                                  \
    asm volatile("pushq %1\n\t"                                                                                                            \
                 "pushq %0\n\t"                                                                                                            \
                 :                                                                                                                         \
                 : "r"((uint64_t)type), "r"((uint64_t)value)                                                                               \
                 : "memory");

    // ORDER OF AUXV ENTRIES:
    // 1. (if vdso enabled) AT_SYSINFO_EHDR
    // 2. AT_MINSIGSTKSZ
    //
    // 3. AT_HWCAP
    // 4. AT_PAGESZ
    // 5. AT_CLKTCK
    // 6. AT_PHDR
    // 7. AT_PHENT
    // 8. AT_PHNUM
    // 9. AT_BASE
    // 10. AT_FLAGS
    // 11. AT_ENTRY
    // 12. AT_UID
    // 13. AT_EUID
    // 14. AT_GID
    // 15. AT_EGID
    // 16. AT_SECURE
    // 17. AT_RANDOM
    // 18. AT_HWCAP2??
    // 19. AT_EXECFN
    // 20. AT_PLATFORM
    // 21. AT_RSEQ_FEATURE_SIZE
    // 22. AT_RSEQ_ALIGN
    // 23. AT_NULL

    // this is the NULL from the end of the kernel stuff (argv strings, envp strings, etc). because we are resetting the second part of the
    // stack, we should push NULL to have the alignment correct.
    asm volatile("pushq $0\n\t" : : : "memory");
    _GOBLIN_SET_AUXV_ENT(AT_NULL, 0);
    _GOBLIN_SET_AUXV_ENT(AT_RSEQ_ALIGN, get_org_auxv_entry(auxv, AT_RSEQ_ALIGN));
    _GOBLIN_SET_AUXV_ENT(AT_RSEQ_FEATURE_SIZE, get_org_auxv_entry(auxv, AT_RSEQ_FEATURE_SIZE));
    _GOBLIN_SET_AUXV_ENT(AT_PLATFORM, get_org_auxv_entry(auxv, AT_PLATFORM));
    _GOBLIN_SET_AUXV_ENT(AT_EXECFN, get_org_auxv_entry(auxv, AT_EXECFN));
    // _GOBLIN_SET_AUXV_ENT(AT_HWCAP2, 0); // not used in x86_64 i think
    _GOBLIN_SET_AUXV_ENT(AT_RANDOM, get_org_auxv_entry(auxv, AT_RANDOM));
    // if not provided by the kernel
    _GOBLIN_SET_AUXV_ENT(AT_SECURE, get_org_auxv_entry(auxv, AT_SECURE));
    _GOBLIN_SET_AUXV_ENT(AT_EGID, get_org_auxv_entry(auxv, AT_EGID));
    _GOBLIN_SET_AUXV_ENT(AT_GID, get_org_auxv_entry(auxv, AT_GID));
    _GOBLIN_SET_AUXV_ENT(AT_EUID, get_org_auxv_entry(auxv, AT_EUID));
    _GOBLIN_SET_AUXV_ENT(AT_UID, get_org_auxv_entry(auxv, AT_UID));
    _GOBLIN_SET_AUXV_ENT(AT_ENTRY, m_elf_header.e_entry);
    _GOBLIN_SET_AUXV_ENT(AT_FLAGS, get_org_auxv_entry(auxv, AT_FLAGS));
    _GOBLIN_SET_AUXV_ENT(AT_BASE, m_load_base_addr);
    _GOBLIN_SET_AUXV_ENT(AT_PHNUM, m_elf_header.e_phnum);
    _GOBLIN_SET_AUXV_ENT(AT_PHENT, m_elf_header.e_phentsize);
    char *phdr = new char[m_elf_header.e_phentsize * m_elf_header.e_phnum];
    m_elf_file.seekg(m_elf_header.e_phoff);
    m_elf_file.read(phdr, m_elf_header.e_phentsize * m_elf_header.e_phnum);
    _GOBLIN_SET_AUXV_ENT(AT_PHDR, phdr);
    _GOBLIN_SET_AUXV_ENT(AT_CLKTCK, get_org_auxv_entry(auxv, AT_CLKTCK));
    _GOBLIN_SET_AUXV_ENT(AT_PAGESZ, PAGE_SIZE);
    _GOBLIN_SET_AUXV_ENT(AT_HWCAP, get_org_auxv_entry(auxv, AT_HWCAP));
    _GOBLIN_SET_AUXV_ENT(AT_MINSIGSTKSZ, get_org_auxv_entry(auxv, AT_MINSIGSTKSZ));
    _GOBLIN_SET_AUXV_ENT(AT_SYSINFO_EHDR,
                         get_org_auxv_entry(auxv, AT_SYSINFO_EHDR)); // FIXME: need to check if vdso is enabled before pushing this
    asm volatile("pushq $0\n\t" : : : "memory");
}
#undef _GOBLIN_SET_AUXV_ENT

__attribute__((noreturn)) void Executable::run(int exec_argc, char **exec_argv, char **exec_envp) {
    build_shared_objs_tree(m_exec_shared);
    init_tls();
    apply_post_tls_init_relocations();

#ifdef DEBUG
    if (m_dyn_seg_index > 0) {
        print_dynamic_segment();
    }
#endif

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

    {
        int exec_envpc = 0; // FIXME: this should never be a stack variable. always
        for (; exec_envp[exec_envpc] != NULL; exec_envpc++)
            ;
        push_auxv_entries(reinterpret_cast<Elf64_auxv_t *>(exec_envp + exec_envpc + 1));
        push_argv_envp_entries(exec_envpc, exec_envp);
        asm volatile("pushq $0\n\t" : : : "memory");
        push_argv_envp_entries(exec_argc, exec_argv);
    }
// push argc, set rdi to 'atexit', and finally jump to entry point
#define _GOBLIN__START (reinterpret_cast<void (*)(void)>(m_load_base_addr + m_elf_header.e_entry))
#define _GOBLIN__ATEXIT ((void *)(_GOBLIN_GI(atexit)))
    asm volatile("pushq %0\n\t"
                 "lea (%1), %%rdi\n\t"
                 "jmp *%2\n\t"
                 :
                 : "r"((uint64_t)exec_argc), "r"(_GOBLIN__ATEXIT), "r"(_GOBLIN__START)
                 : "memory");
#undef _GOBLIN__ATEXIT
#undef _GOBLIN__START

    exit(0);
}
} // namespace Goblin
