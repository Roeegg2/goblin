#include "../include/runner.hpp"

#include <iostream>

namespace Roee_ELF {
constexpr Elf64_Addr executable_base_addr = 0x400000;

    Runner::Runner(const char* file_path) : Loader(file_path, executable_base_addr){

    }

    Runner::~Runner(void){

    }

    void Runner::link_external_libs(void){

    }

    void Runner::apply_dyn_relocations(void) {
        if (dyn_seg_index < 0){
            return;
        }

        for (Elf64_Word i = 0; i < (dyn_rela.total_size / dyn_rela.entry_size); i++) {
            Elf64_Addr* addr = reinterpret_cast<Elf64_Addr*>(dyn_rela.addr[i].r_offset + load_base_addr);
            switch (ELF64_R_TYPE(dyn_rela.addr[i].r_info)) {
                case R_X86_64_RELATIVE:
                    *addr = dyn_rela.addr[i].r_addend + load_base_addr;
                    break;
                case R_X86_64_64:
                    *addr = dyn_rela.addr[i].r_addend + load_base_addr;
                    break;
                case R_X86_64_COPY:
                    *addr = *reinterpret_cast<Elf64_Addr*>(dyn_rela.addr[i].r_addend + load_base_addr);
                    break;
                default:
                    std::cerr << "Unknown relocation type\n";
                    exit(1);
            }
        }
    }

    void Runner::run(void){ // elf_header.e_entry 0x401655
        map_dyn_segment();
        parse_dyn_segment();
        map_load_segments();
        apply_dyn_relocations();
        link_external_libs();
        set_correct_permissions();

#ifdef DEBUG
        print_dynamic_segment();
        std::cout << "Starting execution...\n";
#endif
        void (*start_execution)(void) = reinterpret_cast<void(*)()>(elf_header.e_entry + load_base_addr);
        start_execution();
    }
}
