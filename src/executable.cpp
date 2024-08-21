#include "../include/executable.hpp"

#include <cstring>
#include <elf.h>
#include <iostream>

namespace Roee_ELF {
    Executable::Executable(const char* file_path) : Loadable(file_path, executable_base_addr){

    }

    Executable::~Executable(void){

    }

    void Executable::resolve_symbols_from_external_lib(Elf64_Sym* lib_dyn_sym, const char* lib_dyn_str, const Elf64_Addr lib_base_addr) {
        // for (Elf64_Xword i = 0; i < (lib_dyn_sym->st_size / lib_dyn_sym->st_info); i++) {
        //     if (lib_dyn_sym[i].st_name == 0) {
        //         continue;
        //     }
        //     std::string lib_sym_name = lib_dyn_str + lib_dyn_sym[i].st_name;
        //     for (auto sym : needed_symbols) {
        //         std::string org_sym_name = dyn_str + dyn_sym[sym].st_name;
        //         if (lib_sym_name == org_sym_name) {
        //             *reinterpret_cast<Elf64_Addr*>(dyn_sym[sym].st_value + load_base_addr) =
        //                 lib_dyn_sym[i].st_value + lib_base_addr;

        //             needed_symbols.erase(std::remove(needed_symbols.begin(),
        //                 needed_symbols.end(), sym), needed_symbols.end());
        //         }
        //     }
        // }

        lib_dyn_sym++;
        // while (*lib_dyn_sym != nullptr) {
            if (lib_dyn_sym->st_name == 0) {
                // continue;
            }
            std::string lib_sym_name = lib_dyn_str + lib_dyn_sym->st_name;
            for (auto sym : needed_symbols) {
                std::string org_sym_name = dyn_str + dyn_sym[sym].st_name;
                if (lib_sym_name == org_sym_name) {
                    char* src = reinterpret_cast<char*>(dyn_sym[sym].st_value + load_base_addr);
                    const char* dst = reinterpret_cast<const char*>(lib_dyn_sym->st_value + lib_base_addr);
                    strcpy(src, dst);

                    // needed_symbols.erase(std::remove(needed_symbols.begin(),
                    //     needed_symbols.end(), sym), needed_symbols.end());
                }
            }
            lib_dyn_sym++;
        // }
    }

    // void Executable::parse_dyn_sym_section() {
    //     for (Elf64_Xword i = 0; i < (dyn_sym->st_size / dyn_sym->st_info); i++) {
    //         Elf64_Sym* sym = reinterpret_cast<Elf64_Sym*>(dyn_sym->st_value + i * dyn_sym->st_info);
    //         if (sym->st_name == 0) {
    //             continue;
    //         }
    //         char* sym_name = reinterpret_cast<char*>(dyn_str + sym->st_name);
    //         switch (ELF64_ST_TYPE(sym->st_info)) {
    //         case STT_FUNC:
    //         case STT_OBJECT:
    //         case STT_NOTYPE:
    //             needed_symbols.push_back(i);
    //             break;
    //         default:
    //             std::cerr << "Unknown symbol type\n";
    //             break;
    //         }
    //     }
    // }

    void Executable::link_external_libs(void) {
        for (auto lib : shared_objs_dependency_tree) {
            std::string lib_name = dyn_str + lib; // base_addr + str section + offset into str section
            std::ifstream lib_file("/lib/x86_64-linux-gnu/" + lib_name, std::ios::binary);
            // ADD SUPPORT FOR MORE LIBRARY PATHS
            if (!lib_file.is_open()) {
                std::cerr << "Failed to open library: " << lib_name << "\n";
                exit(1);
            }

            Loadable* lib_elf_file = new Loadable(("/lib/x86_64-linux-gnu/" + lib_name).c_str(), libs_base_addr);
            lib_elf_file->parse_elf_header();
            lib_elf_file->parse_prog_headers();
            lib_elf_file->map_dyn_segment();
            lib_elf_file->parse_dyn_segment();
            lib_elf_file->map_load_segments();

            resolve_symbols_from_external_lib(lib_elf_file->dyn_sym, lib_elf_file->dyn_str, lib_elf_file->load_base_addr);

            lib_elf_file->set_correct_permissions();
        }
    }

    void Executable::apply_dyn_relocations(void) {
        if (dyn_seg_index < 0){
            return;
        }

        for (Elf64_Word i = 0; i < (dyn_rela.total_size / dyn_rela.entry_size); i++) {
            Elf64_Addr* addr = reinterpret_cast<Elf64_Addr*>(dyn_rela.addr[i].r_offset + load_base_addr);
            Elf64_Sym* sym = reinterpret_cast<Elf64_Sym*>(dyn_sym + ELF64_R_SYM(dyn_rela.addr[i].r_info));
            switch (ELF64_R_TYPE(dyn_rela.addr[i].r_info)) {
                case R_X86_64_RELATIVE:
                    *addr = dyn_rela.addr[i].r_addend + load_base_addr;
                    break;
                case R_X86_64_64:
                    *addr = dyn_rela.addr[i].r_addend + load_base_addr + sym->st_value;
                    break;
                case R_X86_64_COPY:
                    needed_symbols.push_back(i);
                    // *addr = *reinterpret_cast<Elf64_Addr*>(dyn_rela.addr[i].r_addend + load_base_addr);
                    break;
                default:
                    std::cerr << "Unknown relocation type\n";
                    exit(1);
            }
        }
    }

    void Executable::run(void) { // elf_header.e_entry 0x401655
        map_dyn_segment();
        parse_dyn_segment();
        map_load_segments();
        apply_dyn_relocations();
        // build_shared_objs_dep_graph();
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
