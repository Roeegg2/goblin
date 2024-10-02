#ifndef GOBLIN_LOADABLE_HPP
#define GOBLIN_LOADABLE_HPP

#include "elf_file.hpp"
#include "utils.hpp"

#include <array>
#include <cstdint>
#include <cwctype>
#include <elf.h>
#include <functional>
#include <set>
#include <vector>

namespace Goblin {
class Loadable;
// should i use inline here?
inline constexpr const auto BINDING_EAGER = 0b0;
inline constexpr const auto BINDING_LAZY = 0b1;
inline constexpr const auto BINDING_OPTIMAL = BINDING_LAZY;
inline constexpr const auto SYMBOL_RESOLUTION_ELF_HASH = 0b00;
inline constexpr const auto SYMBOL_RESOLUTION_GNU_HASH = 0b01;
inline constexpr const auto SYMBOL_RESOLUTION_SYMTAB = 0b10;
inline constexpr const auto SYMBOL_RESOLUTION_OPTIMAL = SYMBOL_RESOLUTION_GNU_HASH;

typedef struct {
    uint64_t binding : 1;
    uint64_t symbol_resolution : 2;
} options_t;

struct hash_tab_data {
    // shared stuff
    uint32_t nbuckets;
    uint32_t *buckets;
    uint32_t *chains;
    // gnu hash specific
    union {
        uint32_t nchains;
        uint32_t symoffset;
    }; // could be grouped together so why not :)

    uint32_t bloom_size;
    uint32_t bloom_shift;
    uint64_t *bloom;
};

struct tls_img {
    Elf64_Word m_module_id;
    Elf64_Xword m_size;
    void *m_data;
    Elf64_Off m_tlsoffset;
    bool m_is_static_model;
};

struct tls {
    std::vector<struct tls_img> m_init_imgs;
    Elf64_Off m_total_imgs_size;
};

struct executable_shared {
    id_t m_glibc_modid = 0; // no ID can be 0 so we can mark 0 as unset (TLS modids start from 1)
    IDs m_mod_ids;
    struct tls m_tls;
}; // stuff shared between the executable and it's loaded shared objects

struct rela_table {
    Elf64_Rela *m_addr;
    Elf64_Xword m_total_size;
    static constexpr Elf64_Xword s_ENTRY_SIZE = 24;
};

struct relr_table {
    Elf64_Relr *m_addr;
    Elf64_Xword m_total_size;
    static constexpr Elf64_Xword s_ENTRY_SIZE = 8;
};

struct extern_rela {
    std::string (*f_construct_name)(const char *, const Elf64_Word);
    void (*f_apply_relocation)(Loadable *self, const Loadable *dep, const Elf64_Word sym_index, const uint32_t i);
    std::set<Elf64_Word> m_syms;
};

// would've used enum class but it's not possible to use it as an index in an array...
enum ExternRelasIndices : uint8_t {
    REL_COPY = 0,
    REL_JUMPS_GLOBD,
    REL_TLS_DTPMOD64,
    ExternRelasIndices_SIZE,
};

class Loadable : public ELF_File {
  public:
    Loadable(const std::string file_path, const options_t options);
    ~Loadable();
#ifdef DEBUG
    void print_dynamic_segment(void) const;
    void print_dynamic_tag(const Elf64_Sxword tag) const;
#endif
    void build_shared_objs_tree(struct executable_shared &exec_shared);

  protected:
    void parse_dyn_segment(std::set<Elf64_Xword> &m_dt_needed_syms);
    bool check_n_handle_new_dep(const Elf64_Xword dt_needed);
    bool check_n_handle_loaded_dep(const Elf64_Xword dt_needed);
    inline void construct_loadables_for_shared_objects(const std::set<Elf64_Xword> &m_dt_needed_syms);

    bool resolve_path_rpath_runpath(const char *r_run_path, std::string &path, const char *shared_obj_name) const;
    static bool resolve_path_ld_library_path(std::string &path, const char *shared_obj_name);
    static bool resolve_path_default(std::string &path, const char *shared_obj_name);

    void alloc_mem_for_segments(void);
    void map_segments(struct tls *tls, const id_t mod_id);
    void setup_segment(const Elf64_Word i);
    void set_correct_permissions(void);
    void apply_plt_rela_relocations(void);
    void apply_dyn_rela_relocations(void);
    void apply_dyn_relr_relocations(void);
    void apply_external_dyn_relocations(Loadable *dep);
    void apply_tls_relocations(const id_t mod_id);
    void init_extern_relas(void);

    static int elf_perm_to_mmap_perms(const uint32_t elf_flags);
    uint32_t get_total_page_count(void) const;

    Elf64_Sym *lookup_regular_dynsym(const char *sym_name) const;
    Elf64_Sym *lookup_elf_hash_dynsym(const char *sym_name) const;
    Elf64_Sym *lookup_gnu_hash_dynsym(const char *sym_name) const;
    uint8_t set_sym_lookup_method(void);
    void init_hash_tab_data(const uint8_t lookup_method);

    void handle_if_module_is_glibc(struct executable_shared &exec_shared, const id_t mod_id) const;

  protected:
    options_t m_options;
    int16_t m_dyn_seg_index;
    int16_t m_tls_seg_index;
    Elf64_Addr m_load_base_addr;
    std::vector<void *> m_segment_data;

  private:
    char *m_rpath;
    char *m_runpath;
    struct {
        struct rela_table rela;
        struct relr_table relr;
        Elf64_Sym *sym_table;
        char *str_table;
    } m_dyn;

    struct {
        struct rela_table rela;
        Elf64_Addr *got;
    } m_plt;

    struct {
        uint16_t gnu_hash;
        uint16_t elf_hash;
        uint16_t dynsym;
    } m_sht_indices;
    struct hash_tab_data m_hash_data;

    std::set<Loadable *> m_dependencies; // list of each dependency's Loadable object. only this object's m_dependencies
    std::array<struct extern_rela, ExternRelasIndices::ExternRelasIndices_SIZE>
        m_extern_relas;                     // indices of symbols that are needed from the external libraries
    std::set<Elf64_Xword> m_dt_needed_syms; // list of DT_NEEDED entries - list of SOs we need to load
    std::set<Elf64_Word> m_tls_relas;       // indices of symbols that are needed for TLS relocations

    // static Loadable &glibc_loadable;
    static std::vector<Loadable *> s_loaded_dependencies;
    static const char *s_DEFAULT_SHARED_OBJ_PATHS[];

    std::function<Elf64_Sym *(const char *)> f_lookup_dynsym;
};
}; // namespace Goblin

#endif
