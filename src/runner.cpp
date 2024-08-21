#include "../include/runner.hpp"
#ifdef DEBUG
#include <iostream>
#endif
namespace Roee_ELF {
constexpr Elf64_Addr executable_base_addr = 0x400000;

    Runner::Runner(const char* file_path) : Loader(file_path, executable_base_addr){

    }

    Runner::~Runner(void){

    }

    void Runner::run(void){ // elf_header.e_entry 0x401655
        map_dyn_segment();
        parse_dyn_segment();
        map_load_segments();
        apply_dyn_relocations();
        // link_external_libs();
        set_correct_permissions();

#ifdef DEBUG
        print_dynamic_segment();
        std::cout << "Starting execution...\n";
#endif
        void (*start_execution)(void) = reinterpret_cast<void(*)()>(elf_header.e_entry + load_base_addr);
        start_execution();
    }
}
