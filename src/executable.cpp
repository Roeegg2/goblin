#include "../include/executable.hpp"

#include <cstring>
#include <elf.h>
#include <iostream>
#include <sys/mman.h>

/*prefix Goblin internal assembly functions (to avoid naming collision with
 * other libraries and stuff)*/
#define GI(sym) _goblin_##sym

extern "C" {
void GI(tls_init_tp)(void *tp);
void *GI(tls_get_tp)(void);
}

namespace Goblin {
Executable::Executable(const std::string file_path, const options_t options) : Loadable(file_path, options) {}

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
    GI(tls_init_tp)(tp); // set the thread pointer to point to the tcb

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

void Executable::cleanup(void) { return; }

void Executable::run(void) {
    build_shared_objs_tree(m_exec_shared);

    init_thread_static_tls();

#ifdef DEBUG
    if (m_dyn_seg_index > 0) {
        print_dynamic_segment();
    }
#endif
    std::cout << "\nStarting execution..." << std::endl;
    cleanup();
    // FIXME: get rid of not used anymore stuff

    void (*start_execution)(void) = reinterpret_cast<void (*)()>(m_elf_header.e_entry + m_load_base_addr);
    start_execution();
}
}; // namespace Goblin
