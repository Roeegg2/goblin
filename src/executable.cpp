#include "../include/executable.hpp"

#include <cstring>
#ifdef DEBUG
#include <iostream>
#endif
#include <elf.h>
#include <sys/mman.h>

namespace Goblin {
    Executable::Executable(std::string file_path)
        : Loadable(file_path) { }

    Executable::~Executable(void) { }

    void Executable::run(void) { // elf_header.e_entry 0x401655
        build_shared_objs_tree();

#ifdef DEBUG
        if (dyn_seg_index > 0) {
            print_dynamic_segment();
            std::cout << "Starting execution...\n";
        }
#endif
        void (*start_execution)(void) = reinterpret_cast<void(*)()>(elf_header.e_entry + load_base_addr);
        start_execution();
    }
}
