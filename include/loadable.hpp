#ifndef RUNNER_HPP
#define RUNNER_HPP

#include "elf_file.hpp"

#include <elf.h>
#include <list>
#include <memory>

#define PAGE_ALIGN_DOWN(addr) ((addr) & ~(PAGE_SIZE-1))

namespace Roee_ELF {
    constexpr Elf64_Addr libs_base_addr = 0x600000;
    constexpr uint16_t PAGE_SIZE = 0x1000;

    class Loadable : public ELF_File {
    public:
        Loadable(const char* file_path, const Elf64_Addr load_base_addr);
        ~Loadable();
#ifdef DEBUG
        void print_dynamic_segment(void) const;
        void print_dynamic_tag(Elf64_Sxword tag) const;
#endif
        void parse_dyn_segment(void);
        void map_dyn_segment(void);
        void map_load_segments(void);
        void set_correct_permissions(void);
        void apply_dep_dyn_relocations(std::shared_ptr<Loadable> dep);
        void apply_basic_dyn_relocations(void);

    protected:
        static uint8_t get_page_count(Elf64_Xword memsz, Elf64_Addr addr);
        static int elf_perm_to_mmap_perms(uint32_t const elf_flags);

        void build_shared_objs_tree(void);

    public:
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

        std::list<Elf64_Word> needed_symbols; // indices of symbols that are needed from the external libraries
        std::list<std::shared_ptr<Loadable>> dependencies; // list of Loader objects that contain the needed symbols
    };
}

#endif
