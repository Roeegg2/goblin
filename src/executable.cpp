#include "../include/executable.hpp"

#include <cstring>
#if defined(DEBUG) || defined(INFO)
#include <iostream>
#endif
#include <elf.h>
#include <sys/mman.h>

namespace Goblin {
    Executable::Executable(const std::string file_path)
        : Loadable(file_path) { }

    Executable::~Executable(void) { }

    void Executable::run(void) { // elf_header.e_entry 0x401655
        build_shared_objs_tree();

#ifdef DEBUG
        if (dyn_seg_index > 0) {
            print_dynamic_segment();
        }
#endif
#ifdef INFO
        std::cout << "\nStarting execution...\n";
#endif
        munmap(segment_data[dyn_seg_index], prog_headers[dyn_seg_index].p_memsz); // Goblin finished doing its magic, so there is no need for the dynamic segment anymore
        void (*start_execution)(void) = reinterpret_cast<void(*)()>(elf_header.e_entry + load_base_addr);
        start_execution();
    }
}
