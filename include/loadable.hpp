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
        Elf64_Rela* m_addr;
        Elf64_Xword m_total_size;
        static constexpr Elf64_Xword s_ENTRY_SIZE = 24;
    };

    struct extern_rela {
        std::string (*f_construct_name)(const char*, const Elf64_Word);
        void (*f_apply_relocation)(Loadable* self, const std::shared_ptr<Loadable>& dep, const Elf64_Word sym_index, const uint32_t i);
        std::set<Elf64_Word> m_syms;
    };
	
	struct tls_img {
		Elf64_Word m_module_id; 
		Elf64_Xword m_size;
		void* m_data;
		Elf64_Off m_tlsoffset;
		bool m_is_static_model;
	};

	struct tls {
		std::vector<struct tls_img> m_init_imgs;
		Elf64_Off m_total_imgs_size;
	};
    // would've used enum class but it's not possible to use it as an index in an array...
    enum ExternRelasIndices : uint8_t {
        REL_COPY = 0,
        REL_JUMPS_GLOBD = 1,
    };

    class Loadable : public ELF_File {
    public:
        Loadable(const std::string file_path, const Elf64_Word module_id);
        ~Loadable();
#ifdef DEBUG
        void print_dynamic_segment(void) const;
        void print_dynamic_tag(const Elf64_Sxword tag) const;
#endif
        // bool find_file(const std::filesystem::path& directory, const std::string& filename, std::string& found_path);
        void build_shared_objs_tree(void);
    protected:
        void parse_dyn_segment(std::set<Elf64_Xword>& m_dt_needed_syms);
        void construct_loadeables_for_shared_objects(const std::set<Elf64_Xword>& m_dt_needed_syms);

        bool resolve_path_rpath_runpath(const char* r_run_path, std::string& path, const char* shared_obj_name) const;
        static bool resolve_path_ld_library_path(std::string& path, const char* shared_obj_name);
        static bool resolve_path_default(std::string& path, const char* shared_obj_name);

        void alloc_mem_for_segments(void);
        void map_segments(void);
        void set_correct_permissions(void);
        void apply_external_dyn_relocations(const std::shared_ptr<Loadable>& dep);
        void apply_basic_dyn_relocations(const struct rela_table& rela);
		void apply_tls_relocations(void); 

        static int elf_perm_to_mmap_perms(const uint32_t elf_flags);
        inline static uint32_t get_page_count(const Elf64_Xword memsz, const Elf64_Addr addr);
        uint32_t get_total_page_count(void) const;

    protected:
        int16_t m_dyn_seg_index;
        int16_t m_tls_seg_index;
        Elf64_Addr m_load_base_addr;
        std::vector<void*> m_segment_data;
		static struct tls s_tls;

    private:
		Elf64_Word m_module_id;
        char* m_rpath;
        char* m_runpath;
        struct {
            struct rela_table rela_table;
            Elf64_Sym* sym_table;
            char* str_table;
        } m_dyn;

        struct {
            rela_table rela;
            Elf64_Addr* got;
        } m_plt;

        std::set<std::shared_ptr<Loadable>> m_dependencies; // list of each dependency's Loadable object. only this object's m_dependencies
        std::array<struct extern_rela, 2> m_extern_relas; // indices of symbols that are needed from the external libraries
        std::set<Elf64_Xword> m_dt_needed_syms; // list of DT_NEEDED entries - list of SOs we need to load
		std::set<Elf64_Word> m_tls_relas; // indices of symbols that are needed for TLS relocations

        static const char* s_DEFAULT_SHARED_OBJ_PATHS[];
    };
}

#endif
