#include "../include/runner.hpp"
#include "../include/utils.hpp"

#include <cstdint>
#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <iostream>

namespace Roee_ELF {
    Runner::Runner(const char* file_path) : Parser_64b(file_path) {
        elf_file_fd = open(file_path, O_RDONLY);
        if (elf_file_fd == -1) {
            std::cerr << "Failed to open file\n";
            exit(1);
        }

        full_parse();
        if (elf_header.e_type != ET_EXEC)
            load_base_addr = 0x400000;
        else
            load_base_addr = 0x0;
    }

    void Runner::handle_relocations(void) {
        // dynamic relocations
        if (dyn_seg_index < 0){
            return;
        }
        Elf64_Dyn* dyn_table = reinterpret_cast<Elf64_Dyn*>(segment_data[dyn_seg_index]);
        while (dyn_table->d_tag != DT_NULL) {
            if (dyn_table->d_tag == DT_RELA) {
                apply_dyn_relocations(dyn_table->d_un.d_ptr);
                return;
            }
            dyn_table++;
        }
    }

    void Runner::apply_dyn_relocations(Elf64_Off rela_table) {
        Elf64_Rela* rela = reinterpret_cast<Elf64_Rela*>(rela_table + load_base_addr);
        while (rela->r_offset != 0) {
            Elf64_Addr* addr = reinterpret_cast<Elf64_Addr*>(rela->r_offset + load_base_addr);
            switch (ELF64_R_TYPE(rela->r_info)) {
                case R_X86_64_RELATIVE:
                    *addr = rela->r_addend + load_base_addr;
                    break;
                case R_X86_64_64:
                    *addr = rela->r_addend + load_base_addr;
                    break;
                case R_X86_64_COPY:
                    *addr = *reinterpret_cast<Elf64_Addr*>(rela->r_addend + load_base_addr);
                    break;
                default:
                    std::cerr << "Unknown relocation type\n";
                    exit(1);
            }
            rela++;
        }
    }

    void Runner::map_dyn_segment(void) {
        if (dyn_seg_index < 0) {
            return;
        }
        segment_data[dyn_seg_index] = mmap(NULL, prog_headers[dyn_seg_index].p_memsz, PROT_READ | PROT_WRITE,
            MAP_PRIVATE, elf_file_fd, PAGE_ALIGN_DOWN(prog_headers[dyn_seg_index].p_offset));

        // add back to segment_data the offset that was removed by the page alignment (stupid mmap...)
        segment_data[dyn_seg_index] = reinterpret_cast<void*>(reinterpret_cast<Elf64_Addr>(segment_data[dyn_seg_index]) +
            prog_headers[dyn_seg_index].p_offset - PAGE_ALIGN_DOWN(prog_headers[dyn_seg_index].p_offset));
    }

    uint8_t Runner::get_page_count(Elf64_Xword memsz, Elf64_Addr addr) {
        addr = addr % PAGE_SIZE;
        return ((memsz + addr) / PAGE_SIZE) + 1;
    }

    void Runner::map_load_segments(void) {
        for (int8_t i = 0; i < elf_header.e_phnum; i++) {
            if (prog_headers[i].p_type == PT_LOAD && prog_headers[i].p_memsz > 0) {
                {
                    // get page count to alloacte
                    uint8_t page_count = get_page_count(prog_headers[i].p_memsz, prog_headers[i].p_vaddr);
                    // allocate memory for the segment
                    segment_data[i] = mmap(reinterpret_cast<void*>(PAGE_ALIGN_DOWN(prog_headers[i].p_vaddr) + load_base_addr),
                        page_count * PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE,
                        elf_file_fd, PAGE_ALIGN_DOWN(prog_headers[i].p_offset));
                }

                // if some error occured
                if (reinterpret_cast<Elf64_Addr>(segment_data[i]) > 0xffffffffffffff00) {
                    std::cerr << "i is: " << i << "\n";
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

    void Runner::set_correct_permissions(void) {
        for (int8_t i = 0; i < elf_header.e_phnum; i++) {
            if (prog_headers[i].p_type == PT_LOAD && prog_headers[i].p_memsz > 0) {
                if (mprotect(reinterpret_cast<void*>(PAGE_ALIGN_DOWN(reinterpret_cast<Elf64_Addr>(segment_data[i]))),
                    prog_headers[i].p_memsz, elf_perm_to_mmap_perms(prog_headers[i].p_flags)) == -1) {
                    std::cerr << "mprotect failed\n";
                    exit(1);
                }
            }
        }
    }

    void Runner::run(void) { //elf_header.e_entry 0x401655
        segment_data = new void*[elf_header.e_phnum];

        if (dyn_seg_index >= 0) {
            map_dyn_segment();
        }
        map_load_segments();
        handle_relocations();
        set_correct_permissions();

#ifdef DEBUG
        print_dynamic_segment();
        std::cout << "Starting execution...\n";
#endif
        start_execution = reinterpret_cast<void(*)()>(elf_header.e_entry + load_base_addr); // turn the code segment start into a function ptr
        start_execution(); // execute executable code
    }
}
