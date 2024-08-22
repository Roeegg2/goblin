#include "../include/executable.hpp"

#ifdef DEBUG
#include <iostream>
#endif
#include <elf.h>

namespace Roee_ELF {
    Executable::Executable(const char* file_path)
        : Loadable(file_path) { }

    Executable::~Executable(void) { }

    void Executable::run(void) { // elf_header.e_entry 0x401655
        build_shared_objs_tree();

#ifdef DEBUG
        print_dynamic_segment();
        std::cout << "Starting execution...\n";
#endif
        void (*start_execution)(void) = reinterpret_cast<void(*)()>(elf_header.e_entry + load_base_addr);
        start_execution();
    }
}
