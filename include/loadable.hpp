#ifndef RUNNER_HPP
#define RUNNER_HPP

#include "elf_file.hpp"

#include <elf.h>
#include <set>
#include <memory>
#include <vector>
#include <array>

#define PAGE_ALIGN_DOWN(addr) ((addr) & ~(PAGE_SIZE-1))

namespace Goblin {
    constexpr uint16_t PAGE_SIZE = 0x1000;
    class Loadable;


    struct rela_table {
        Elf64_Rela* addr;
        Elf64_Xword total_size;
        static constexpr Elf64_Xword entry_size = 24;
    };

    struct extern_rela {
        std::string (*construct_name)(const char*, const Elf64_Word);
        void (*apply_relocation)(Loadable* self, const std::shared_ptr<Loadable>& dep, const Elf64_Word sym_index, const uint32_t i);
        std::set<Elf64_Word> syms;
    };

    enum ExternRelasIndices : uint8_t {
        REL_COPY = 0,
        REL_JUMPS_GLOBD = 1,
    };

    class Loadable : public ELF_File {
    public:
        Loadable(const std::string file_path);
        ~Loadable();
#ifdef DEBUG
        void print_dynamic_segment(void) const;
        void print_dynamic_tag(const Elf64_Sxword tag) const;
#endif
        // bool find_file(const std::filesystem::path& directory, const std::string& filename, std::string& found_path);
        void build_shared_objs_tree(void);
    protected:
        void parse_dyn_segment(std::set<Elf64_Xword>& dt_needed_syms);
        void construct_loadeables_for_shared_objects(const std::set<Elf64_Xword>& dt_needed_syms);
        bool resolve_path_rpath_runpath(const char* r_run_path, std::string& path, const char* shared_obj_name) const;
        bool resolve_path_ld_library_path(std::string& path, const char* shared_obj_name);
        bool resolve_path_default(std::string& path, const char* shared_obj_name) const;
        void alloc_mem_for_segments(void);
        void map_segments(void);
        void set_correct_permissions(void);
        void apply_external_dyn_relocations(const std::shared_ptr<Loadable>& dep);
        void apply_basic_dyn_relocations(const struct rela_table& rela);

        static int elf_perm_to_mmap_perms(const uint32_t elf_flags);
        inline static uint32_t get_page_count(const Elf64_Xword memsz, const Elf64_Addr addr);
        uint32_t get_total_page_count(void) const;

    protected:
        int16_t dyn_seg_index;
        Elf64_Addr load_base_addr;
        std::vector<void*> segment_data;

    private:
        int16_t tls_seg_index;
        char* rpath;
        char* runpath;
        struct {
            struct rela_table rela_table;
            Elf64_Sym* sym_table;
            char* str_table;
        } dyn;

        struct {
            rela_table rela;
            Elf64_Addr* got;
        } plt;

        std::array<struct extern_rela, 2> extern_relas; // indices of symbols that are needed from the external libraries
        std::set<Elf64_Xword> dt_needed_syms; // list of DT_NEEDED entries - list of SOs we need to load
        std::set<std::shared_ptr<Loadable>> dependencies; // list of each dependency's Loadable object. only this object's dependencies
        static std::set<std::shared_ptr<Loadable>> global_dependencies; // list of all object's dependencies

        static const char* DEFAULT_SHARED_OBJ_PATHS[];
    };
}

#endif
