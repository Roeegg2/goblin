#include "../include/loader.hpp"
#include "../include/utils.hpp"

#include <cstdint>
#include <cstdlib>
#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <iostream>

namespace Roee_ELF {
constexpr Elf64_Addr libs_base_addr = 0x600000;
    Loader::Loader(const char* file_path, const Elf64_Addr load_base_addr) : Parser_64b(file_path) {
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

    Loader::~Loader(void){
        for (int i = 0; i < elf_header.e_phnum; i++) {
            if (segment_data[i] != nullptr) {
                munmap(segment_data[i], prog_headers[i].p_memsz);
            }
        }
        delete[] segment_data;
        close(mmap_elf_file_fd);
    }

    void Loader::parse_dyn_segment(void) {
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
                dyn_needed_libs.push_back(dyn_table->d_un.d_val);
                break;
            }
            dyn_table++;
        }
    }

    void Loader::apply_dyn_relocations(void) {
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

    void Loader::map_dyn_segment(void) {
        if (dyn_seg_index < 0) {
            return;
        }
        segment_data[dyn_seg_index] = mmap(NULL, prog_headers[dyn_seg_index].p_memsz, PROT_READ | PROT_WRITE,
            MAP_PRIVATE, mmap_elf_file_fd, PAGE_ALIGN_DOWN(prog_headers[dyn_seg_index].p_offset));

        // add back to segment_data the offset that was removed by the page alignment (stupid mmap...)
        segment_data[dyn_seg_index] = reinterpret_cast<void*>(reinterpret_cast<Elf64_Addr>(segment_data[dyn_seg_index]) +
            prog_headers[dyn_seg_index].p_offset - PAGE_ALIGN_DOWN(prog_headers[dyn_seg_index].p_offset));
    }

    uint8_t Loader::get_page_count(Elf64_Xword memsz, Elf64_Addr addr) {
        addr = addr % PAGE_SIZE;
        return ((memsz + addr) / PAGE_SIZE) + 1;
    }

    void Loader::map_load_segments(void) {
        for (int8_t i = 0; i < elf_header.e_phnum; i++) {
            if (prog_headers[i].p_type == PT_LOAD && prog_headers[i].p_memsz > 0) {
                {
                    // get page count to alloacte
                    uint8_t page_count = get_page_count(prog_headers[i].p_memsz, prog_headers[i].p_vaddr);
                    // allocate memory for the segment
                    segment_data[i] = mmap(reinterpret_cast<void*>(PAGE_ALIGN_DOWN(prog_headers[i].p_vaddr) + load_base_addr),
                        page_count * PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE,
                        mmap_elf_file_fd, PAGE_ALIGN_DOWN(prog_headers[i].p_offset));
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

    void Loader::set_correct_permissions(void) {
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

    // void Loader::link_external_libs(void) {
    //     for (auto lib : dyn_needed_libs) {
    //         std::string lib_name = dyn_str + lib; // base_addr + str section + offset into str section
    //         std::ifstream lib_file("/lib/x86_64-linux-gnu/" + lib_name, std::ios::binary);
    //         // ADD SUPPORT FOR MORE LIBRARY PATHS
    //         if (!lib_file.is_open()) {
    //             std::cerr << "Failed to open library: " << lib_name << "\n";
    //             exit(1);
    //         }

    //         Loader* lib_parser = new Loader(("/lib/x86_64-linux-gnu/" + lib_name).c_str(), libs_load_base_addr);
    //         lib_parser->parse_elf_header();
    //         lib_parser->parse_prog_headers();
    //         lib_parser->map_dyn_segment();
    //         lib_parser->parse_dyn_segment();
    //     }



        // for (auto lib : dyn_needed_libs) {
        //     std::string lib_name = dyn_str[lib];
        //     std::string lib_path = "/lib/x86_64-linux-gnu/" + lib_name + ".so";
        //     int lib_fd = open(lib_path.c_str(), O_RDONLY);
        //     if (lib_fd == -1) {
        //         std::cerr << "Failed to open library: " << lib_name << "\n";
        //         exit(1);
        //     }

        //     struct stat lib_stat;
        //     if (fstat(lib_fd, &lib_stat) == -1) {
        //         std::cerr << "Failed to get library stats\n";
        //         exit(1);
        //     }

        //     void* lib_base_addr = mmap(NULL, lib_stat.st_size, PROT_READ, MAP_PRIVATE, lib_fd, 0);
        //     if (lib_base_addr == MAP_FAILED) {
        //         std::cerr << "Failed to map library\n";
        //         exit(1);
        //     }

        //     Elf64_Ehdr* lib_elf_header = reinterpret_cast<Elf64_Ehdr*>(lib_base_addr);
        //     Elf64_Phdr* lib_prog_headers = reinterpret_cast<Elf64_Phdr*>(reinterpret_cast<Elf64_Addr>(lib_base_addr) + lib_elf_header->e_phoff);

        //     for (int8_t i = 0; i < lib_elf_header->e_phnum; i++) {
        //         if (lib_prog_headers[i].p_type == PT_LOAD && lib_prog_headers[i].p_memsz > 0) {
        //             void* lib_segment = mmap(reinterpret_cast<void*>(PAGE_ALIGN_DOWN(lib_prog_headers[i].p_vaddr)),
        //                 get_page_count(lib_prog_headers[i].p_memsz, lib_prog_headers[i].p_vaddr) * PAGE_SIZE,
        //                 PROT_READ, MAP_PRIVATE | MAP_FIXED, lib_fd, PAGE_ALIGN_DOWN(lib_prog_headers[i].p_offset));
        //             if (lib_segment == MAP_FAILED) {
        //                 std::cerr << "Failed to map library segment\n";
        //                 exit(1);
        //             }
        //         }
        //     }
        // }
    // }
}
