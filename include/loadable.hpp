#ifndef RUNNER_HPP
#define RUNNER_HPP

#include "elf_file.hpp"

#include <elf.h>
#include <set>
#include <memory>
#include <vector>
#define PAGE_ALIGN_DOWN(addr) ((addr) & ~(PAGE_SIZE-1))

namespace Roee_ELF {
    constexpr uint16_t PAGE_SIZE = 0x1000;

    struct rela_table {
        Elf64_Rela* addr;
        Elf64_Xword total_size;
        static constexpr Elf64_Xword entry_size = 24;
    };

    class Loadable : public ELF_File {
    public:
        Loadable(std::string file_path);
        ~Loadable();
#ifdef DEBUG
        void print_dynamic_segment(void) const;
        void print_dynamic_tag(Elf64_Sxword tag) const;
#endif
        void parse_dyn_segment(void);
        void map_segments(void);
        void set_correct_permissions(void);
        void apply_dep_dyn_relocations(std::shared_ptr<Loadable> dep);
        void  apply_basic_dyn_relocations(const struct rela_table& rela);

    protected:
        void alloc_mem_for_segments(void);
        static uint8_t get_page_count(Elf64_Xword memsz, Elf64_Addr addr);
        static int elf_perm_to_mmap_perms(uint32_t const elf_flags);
        uint32_t get_total_page_count(void);

        void build_shared_objs_tree(void);

        bool resolve_path_rpath(std::string& path, const char* shared_obj_name) const;
        static bool resolve_path_ld_library_path(std::string& path, const char* shared_obj_name);
        bool resolve_path_default(std::string& path, const char* shared_obj_name) const;


    public:
        Elf64_Addr load_base_addr;
        std::vector<void*> segment_data;

        char* rpath;
        int16_t dyn_seg_index;
        struct {
            struct rela_table rela;
            Elf64_Sym* sym;
            char* str;
        } dyn;

        struct {
            rela_table rela;
            Elf64_Addr* got;
        } plt;

        std::set<Elf64_Word> needed_symbols; // indices of symbols that are needed from the external libraries
        std::set<std::shared_ptr<Loadable>> dependencies; // list of Loader objects that contain the needed symbols

        static const char* DEFAULT_SHARED_OBJ_PATHS[];
    };
}

#endif
