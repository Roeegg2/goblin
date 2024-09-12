#ifndef LOADER_HPP
#define LOADER_HPP

#include "loadable.hpp"

#include <elf.h>
#include <queue>

namespace Goblin {
	typedef Elf64_Word tid_t;

	struct tcb {
		void* tp; // thread pointer (%fs register)
		tid_t tid; // thread id
	};
	
	typedef struct {
		unsigned long int ti_module;
		unsigned long int ti_offset;
	} tls_index;

    class Executable final : public Loadable{
	private:
		void init_thread_static_tls(void);
	
	public:
        Executable(const std::string file_path);
        ~Executable(void);
        void run(void);
	
		void* __tls_get_addr(tls_index* ti);
	private:
		std::vector<struct tcb> m_tcbs;
    	std::vector<std::vector<void*>> dtvs;
		std::queue<tid_t> m_free_tids; // free thread ids
	};
}

#endif
