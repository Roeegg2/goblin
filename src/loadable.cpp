#include "../include/loadable.hpp"

#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <iostream>
#include <cstring>

namespace Roee_ELF {
    Loadable::Loadable(const char* file_path, const Elf64_Addr load_base_addr) : ELF_File(file_path) {
        mmap_elf_file_fd = open(file_path, O_RDONLY);
        if (mmap_elf_file_fd == -1) {
            std::cerr << "Failed to open file\n";
            exit(1);
        }

        full_parse();
        segment_data = new void*[elf_header.e_phnum];

        if (elf_header.e_type != ET_EXEC)
            this->load_base_addr = load_base_addr;
        else
            this->load_base_addr = 0x0;
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
                shared_objs_dependency_tree.push_back(dyn_table->d_un.d_val);
                break;
            }
            dyn_table++;
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

    void Loadable::map_load_segments(void) {
        for (int8_t i = 0; i < elf_header.e_phnum; i++) {
            if (prog_headers[i].p_type == PT_LOAD && prog_headers[i].p_memsz > 0) {
                {
                    // get page count to alloacte
                    const uint16_t page_count = get_page_count(prog_headers[i].p_memsz, prog_headers[i].p_vaddr);
                    // allocate memory for the segment
                    segment_data[i] = mmap(reinterpret_cast<void*>(PAGE_ALIGN_DOWN(prog_headers[i].p_vaddr) + load_base_addr),
                        page_count * PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_FIXED, mmap_elf_file_fd, PAGE_ALIGN_DOWN(prog_headers[i].p_offset));
                }

                // if some error occured
                if (reinterpret_cast<Elf64_Addr>(segment_data[i]) > 0xffffffffffffff00) {
                    std::cerr << "mmap failed BIG TIME\n";
                    exit(1);
                }

                // add back to segment_data the offset that was removed by the page alignment (stupid mmap...)
                segment_data[i] = reinterpret_cast<void*>(prog_headers[i].p_vaddr + load_base_addr);

                // as specified in the ELF64 spec, all memory that isnt mapped from the file should be zeroed
                memset(reinterpret_cast<void*>(reinterpret_cast<Elf64_Addr>(segment_data[i]) + prog_headers[i].p_filesz),
                    0x0, prog_headers[i].p_memsz - prog_headers[i].p_filesz);

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

    // void Loadable::build_shared_objs_dep_graph(void) {
    //     parse_elf_header();
    //     parse_prog_headers();
    //     map_dyn_segment();
    //     parse_dyn_segment();
    //     map_load_segments();

    //     for (auto& shared_obj : shared_obj) {
    //         // std::string lib_name = std::string(dyn_str + lib);
    //         // if (loaded_libs.find(lib_name) == loaded_libs.end()) {
    //         //     loaded_libs[lib_name] = std::make_shared<Loadable>(lib_name);
    //         //     loaded_libs[lib_name]->build_shared_objs_dep_graph();
    //         // }
    //     }
    //     set_correct_permissions();
    // }
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
