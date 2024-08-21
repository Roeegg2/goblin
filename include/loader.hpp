#ifndef RUNNER_HPP
#define RUNNER_HPP

#include "parser.hpp"

#include <list>

#define PAGE_ALIGN_DOWN(addr) ((addr) & ~(PAGE_SIZE-1))

namespace Roee_ELF {
    constexpr uint16_t PAGE_SIZE = 0x1000;

    class Loader : public Parser_64b {
    public:
        Loader(const char* file_path, const Elf64_Addr load_base_addr);
        ~Loader();
#ifdef DEBUG
        void print_dynamic_segment(void) const;
        void print_dynamic_tag(Elf64_Sxword tag) const;
#endif
    protected:
        void parse_dyn_segment(void);
        void map_dyn_segment(void);
        void map_load_segments(void);
        void set_correct_permissions(void);

        static uint8_t get_page_count(Elf64_Xword memsz, Elf64_Addr addr);
        static int elf_perm_to_mmap_perms(uint32_t const elf_flags);

    protected:
        Elf64_Addr load_base_addr;

        void** segment_data;
        int mmap_elf_file_fd; // file descriptor for mma

        struct {
            Elf64_Rela* addr;
            Elf64_Xword total_size;
            Elf64_Xword entry_size;
        } dyn_rela;
        Elf64_Sym* dyn_sym;
        char* dyn_str;

        std::list<Elf64_Xword> dyn_needed_libs;
    };
}

#endif
