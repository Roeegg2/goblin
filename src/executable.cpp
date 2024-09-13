#include "../include/executable.hpp"

#include <cstring>
#if defined(DEBUG) || defined(INFO)
#include <iostream>
#endif
#include <elf.h>
#include <sys/mman.h>

/*prefix Goblin internal assembly functions (to avoid naming collision with other libraries and stuff)*/
#define GI(sym) _goblin_##sym

extern "C" {
	void GI(tls_init_tp)(void* tp);
	void* GI(tls_get_tp)(void);
}

namespace Goblin {
    Executable::Executable(const std::string file_path)
        : Loadable(file_path, 1) { }

    Executable::~Executable(void) {}

    void* Executable::__tls_get_addr(tls_index* ti) {
	    void* tp = _goblin_tls_get_tp();
	    void* tls_block = dtvs[reinterpret_cast<struct tcb*>(tp)->tid][ti->ti_module];

	    if (tls_block == nullptr) {
		/*not handling this yet... we will worry about dlopen loaded modules later.. :)*/
	    }

	    return reinterpret_cast<void*>(reinterpret_cast<Elf64_Addr>(tls_block) + ti->ti_offset); 
    }

    /*code here might cause some confusion. TP here (thread pointer) is point on its right to the TCB, and on the left to the TLS blocks. so in the code its used sometimes for this and sometimes for that*/
    void Executable::init_thread_static_tls() {
		void* tp = mmap(nullptr, s_tls.m_total_imgs_size + sizeof(struct tcb), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); // allocate memory for the tls blocks and tcb, as specified in variant 2
		tp = reinterpret_cast<void*>(reinterpret_cast<Elf64_Addr>(tp) + s_tls.m_total_imgs_size); // we want to point to the end of the tls blocks, and start of the tcb
		GI(tls_init_tp)(tp); // set %fs register to point to the TCB
    	
		/*FIXME: improve this mechanism*/
		struct tcb* ctp = reinterpret_cast<struct tcb*>(tp);
		ctp->tp = tp;
		if (m_free_tids.empty()) { // if there are no free tids, increase the size of the tcb vector
			ctp->tid = m_tcbs.size();
			dtvs.resize(ctp->tid + 1);
		} else { // if there are free tids, just repurpose one
			ctp->tid = m_free_tids.front();
			m_free_tids.pop();
		}

		tp = reinterpret_cast<void*>(reinterpret_cast<Elf64_Addr>(tp) - s_tls.m_total_imgs_size); // point to the start of the tls block images again
		for (auto& img : s_tls.m_init_imgs) { // for each TLS block image
			if (img.m_is_static_model) { // if the TLS block is using static model
				std::memcpy(tp, img.m_data, img.m_size); // copy the TLS block image to the TLS block
				dtvs[ctp->tid].push_back(tp); // NOTE: we initlized the m_init_imgs vector the same order we would've assigned module ids so we can just push_back and not have to worry about the order 
				tp = reinterpret_cast<void*>(reinterpret_cast<Elf64_Addr>(tp) + img.m_size);
			}
		}
    }

    void Executable::run(void) {
        build_shared_objs_tree();

#ifdef DEBUG
        if (m_dyn_seg_index > 0) {
            print_dynamic_segment();
        }
#endif
#ifdef INFO
        std::cout << "\nStarting execution...\n";
#endif
        munmap(m_segment_data[m_dyn_seg_index], m_prog_headers[m_dyn_seg_index].p_memsz); // Goblin finished doing its magic, so there is no need for the dynamic segment anymore
        void (*start_execution)(void) = reinterpret_cast<void(*)()>(m_elf_header.e_entry + m_load_base_addr);
        // void (*start_execution)(void) = reinterpret_cast<void(*)()>(0x1139 + m_load_base_addr);
        start_execution();
    }
}
