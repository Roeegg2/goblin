#include "../include/loadable.hpp"

#include <elf.h>
#include <fcntl.h>
#include <memory>
#include <sys/mman.h>
#include <unistd.h>
#include <iostream>
#include <cstring>
#include <algorithm>

namespace Roee_ELF {
    Loadable::Loadable(const char* file_path)
        : ELF_File(file_path), dyn_rela({0, 0, 0}), dyn_sym(nullptr), dyn_str(nullptr) {
        mmap_elf_file_fd = open(file_path, O_RDONLY);
        if (mmap_elf_file_fd == -1) {
            std::cerr << "Failed to open file\n";
            exit(1);
        }

        full_parse();
        segment_data = new void*[elf_header.e_phnum];
    }

    Loadable::~Loadable(void){
        for (int i = 0; i < elf_header.e_phnum; i++) {
            if (segment_data[i] != nullptr) {
                munmap(segment_data[i], prog_headers[i].p_memsz);
            }
        }
        delete[] segment_data;
        close(mmap_elf_file_fd);
    }

    void Loadable::parse_dyn_segment(void) {
        if (dyn_seg_index < 0){
            return;
        }

        Elf64_Dyn* dyn_table = reinterpret_cast<Elf64_Dyn*>(segment_data[dyn_seg_index]);
        std::set<Elf64_Xword> dt_needed_list;
        while (dyn_table->d_tag != DT_NULL) {
            switch (dyn_table->d_tag) {
            case DT_RELA:
                dyn_rela.addr = reinterpret_cast<Elf64_Rela*>(dyn_table->d_un.d_ptr + load_base_addr);
                break;
            case DT_SYMTAB:
                dyn_sym = reinterpret_cast<Elf64_Sym*>(dyn_table->d_un.d_ptr + load_base_addr);
                break;
            case DT_STRTAB:
                dyn_str = reinterpret_cast<char*>(dyn_table->d_un.d_ptr + load_base_addr);
                break;
            case DT_RELASZ:
                dyn_rela.total_size = dyn_table->d_un.d_val;
                break;
            case DT_RELAENT:
                dyn_rela.entry_size = dyn_table->d_un.d_val;
                break;
            case DT_NEEDED:
                dt_needed_list.insert(dyn_table->d_un.d_val);
                break;
            }
            dyn_table++;
        }

        for (auto dt_needed : dt_needed_list) {
            // NOTE: BEFORE CREATING NEW LOADABLE, CHECK IF IT ALREADY EXISTS
            std::string str = "/home/roeet/Projects/stupidelf/tests/";
            str += dyn_str + dt_needed;
            dependencies.insert(std::make_shared<Loadable>(str.c_str()));
        }
    }

    void Loadable::map_dyn_segment(void) {
        if (dyn_seg_index < 0) {
            return;
        }

        {
            const uint16_t page_count = get_page_count(prog_headers[dyn_seg_index].p_memsz, prog_headers[dyn_seg_index].p_vaddr);
            segment_data[dyn_seg_index] = mmap(NULL, page_count, PROT_READ | PROT_WRITE,
                MAP_PRIVATE, mmap_elf_file_fd, PAGE_ALIGN_DOWN(prog_headers[dyn_seg_index].p_offset));
        }

        // add back to segment_data the offset that was removed by the page alignment (stupid mmap...)
        segment_data[dyn_seg_index] = reinterpret_cast<void*>(reinterpret_cast<Elf64_Addr>(segment_data[dyn_seg_index]) +
            prog_headers[dyn_seg_index].p_offset - PAGE_ALIGN_DOWN(prog_headers[dyn_seg_index].p_offset));
    }

    uint8_t Loadable::get_page_count(Elf64_Xword memsz, Elf64_Addr addr) {
        return (memsz + (addr % PAGE_SIZE) + PAGE_SIZE - 1) / PAGE_SIZE;
    }

    int Loadable::elf_perm_to_mmap_perms(uint32_t const elf_flags) {
        int mmap_flags = 0;

        if (elf_flags & 0x1) mmap_flags |= PROT_EXEC;
        if (elf_flags & 0x2) mmap_flags |= PROT_WRITE;
        if (elf_flags & 0x4) mmap_flags |= PROT_READ;

        return mmap_flags;
    }

    uint32_t Loadable::get_total_page_count(void) {
        uint32_t total_page_count = 0;
        for (int8_t i = 0; i < elf_header.e_phnum; i++) {
            if (prog_headers[i].p_type == PT_LOAD && prog_headers[i].p_memsz > 0) {
                total_page_count += get_page_count(prog_headers[i].p_memsz, prog_headers[i].p_vaddr);
            }
        }

        return total_page_count;
    }

    void Loadable::map_load_segments(void) {
        load_base_addr = prog_headers[0].p_vaddr;

        uint32_t total_page_count = get_total_page_count();
        load_base_addr = reinterpret_cast<Elf64_Addr>(mmap(reinterpret_cast<void*>(load_base_addr),
            total_page_count * PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE,
            mmap_elf_file_fd, 0));

        if (elf_header.e_type == ET_EXEC)
            load_base_addr = 0x0;

        for (int8_t i = 0; i < elf_header.e_phnum; i++) {
            if (prog_headers[i].p_type == PT_LOAD && prog_headers[i].p_memsz > 0) {
                segment_data[i] = reinterpret_cast<void*>(prog_headers[i].p_vaddr + load_base_addr);
            }
        }
    }

    void Loadable::set_correct_permissions(void) {
        for (int8_t i = 0; i < elf_header.e_phnum; i++) {
            if (prog_headers[i].p_type == PT_LOAD && prog_headers[i].p_memsz > 0) {
                const uint16_t page_count = get_page_count(prog_headers[i].p_memsz, prog_headers[i].p_vaddr);

                if (mprotect(reinterpret_cast<void*>(PAGE_ALIGN_DOWN(reinterpret_cast<Elf64_Addr>(segment_data[i]))),
                    page_count * PAGE_SIZE, elf_perm_to_mmap_perms(prog_headers[i].p_flags)) == -1) {
                    std::cerr << "mprotect failed\n";
                    exit(1);
                }
            }
        }
    }

    void Loadable::build_shared_objs_tree(void) {
        map_load_segments();
        map_dyn_segment();
        parse_dyn_segment();
        apply_basic_dyn_relocations();

        for (auto& dep : dependencies) {
            dep->build_shared_objs_tree();
            apply_dep_dyn_relocations(dep);
        }

        // set_correct_permissions();
    }

    void Loadable::apply_dep_dyn_relocations(std::shared_ptr<Loadable> dep) {
        Elf64_Sym* dep_dyn_sym = dep->dyn_sym + 1;
        do {
            std::string lib_sym_name = dep->dyn_str + dep_dyn_sym->st_name;
            for (auto sym : needed_symbols) {
                std::string org_sym_name = dyn_str + dyn_sym[sym].st_name;
                if (lib_sym_name == org_sym_name) {
                    char* src = reinterpret_cast<char*>(dyn_sym[sym].st_value + load_base_addr);
                    const char* dst = reinterpret_cast<const char*>(dep_dyn_sym->st_value + dep->load_base_addr);
                    strcpy(src, dst);

                    // needed_symbols.erase(std::remove(needed_symbols.begin(),
                    //     needed_symbols.end(), sym), needed_symbols.end());
                }
            }
            dep_dyn_sym++;
        } while (ELF64_ST_TYPE(dep_dyn_sym->st_info) != STT_NOTYPE);
    }

    void Loadable::apply_basic_dyn_relocations(void) {
        if (dyn_rela.addr == nullptr){
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
                case R_X86_64_COPY: // advacned relocation type (data is needed from external object)
                    needed_symbols.insert(i);
                    // *addr = *reinterpret_cast<Elf64_Addr*>(dyn_rela.addr[i].r_addend + load_base_addr);
                    break;
                default:
                    std::cerr << "Unknown relocation type\n";
                    exit(1);
            }
        }
    }
}

/*
plan:
1. build dep tree - read each file (starting from current executable)
   parse dyn section and get needed libraries
   if needed lib is already referenced, add shared_ptr it.
   load lib to mem
   for every lib, call the same function (parse dyn section and get needed libraries)

   after the recursion ends, we have a tree of dependencies
   for each node, resolve relocations


*/
