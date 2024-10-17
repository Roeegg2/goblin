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

union hash_tab_data {
    struct {
        uint32_t nbuckets;
        uint32_t nchain;
        uint32_t *bucket;
        uint32_t *chain;
    } elf;
    struct {
        uint32_t nbuckets;
        uint32_t sym_offset;
        uint32_t bloom_size;
        uint32_t bloom_shift;
        uint64_t *bloom;
        uint32_t *bucket;
        uint32_t *chain;
    } gnu;
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
    options_t m_options;
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
    Loadable(const std::string file_path);
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
    void apply_plt_rela_relocations(std::set<Elf64_Word> relas_jumps_globd, std::set<Elf64_Word> relas_irelas,
                                    const uint8_t binding_option);
    void apply_dyn_rela_relocations(std::set<Elf64_Word> &relas_copy, std::set<Elf64_Word> &relas_jumps_globd,
                                    std::set<Elf64_Word> &relas_irelas, std::set<Elf64_Word> &relas_tls_dtpmod64,
                                    std::set<Elf64_Word> &relas_tls_tpoff64, std::set<Elf64_Word> &relas_tls_dtpoff64);
    void apply_relocations_relas_irela(std::set<Elf64_Word> &relas_irelas, const struct rela_table &rela) const;
    void apply_relocations_relas_jumps_globd(Loadable *dep, std::set<Elf64_Word> &relas_jumps_globd);
    void apply_relocations_relas_copy(Loadable *dep, std::set<Elf64_Word> &relas_copy);
    void apply_post_tls_init_relocations(void);
    void apply_relocations_relas_dtpmod64(Loadable *dep, std::set<Elf64_Word> &relas_tls_dtpmod64);
    void apply_relocations_relas_dtpoff64(Loadable *dep, std::set<Elf64_Word> &relas_tls_dtpoff64);
    void apply_relocations_relas_tpoff64(Loadable *dep, std::set<Elf64_Word> &relas_tls_tpoff64);

    void apply_dyn_relr_relocations(void);
    uint32_t get_total_page_count(void) const;

    Elf64_Sym *lookup_regular_dynsym(const char *sym_name) const;
    Elf64_Sym *lookup_elf_hash_dynsym(const char *sym_name) const;
    Elf64_Sym *lookup_gnu_hash_dynsym(const char *sym_name) const;
    uint8_t set_sym_lookup_method(const uint8_t symbol_resolution_option);
    void init_hash_tab_data(const uint8_t lookup_method);

    void handle_if_module_is_glibc(struct executable_shared &exec_shared, const id_t mod_id) const;

  protected:
    int16_t m_dyn_seg_index;
    int16_t m_tls_seg_index;
    Elf64_Addr m_load_base_addr;
    std::vector<void *> m_segment_data;

  private:
    id_t m_mod_id; // FIXME: shouldn't be tied to a Loadable instance, since the same Loadable can be used by many diffrent executables, in
                   // which the Loadable might have a different mod_id
    struct tls_img *m_tls_img; // same thing here
    std::set<Elf64_Word> m_relas_irelas_plt,
        m_relas_irelas_dyn; // ...and same thing here
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

    union hash_tab_data m_hash_data;
    std::function<Elf64_Sym *(const char *)> f_lookup_dynsym;

    std::set<std::shared_ptr<Loadable>> m_dependencies; // list of each dependency's Loadable object. only this object's m_dependencies
    std::set<Elf64_Word> m_tls_relas;                   // indices of symbols that are needed for TLS relocations

    static std::vector<std::shared_ptr<Loadable>> s_loaded_dependencies;
    static const char *s_DEFAULT_SHARED_OBJ_PATHS[];
};
}; // namespace Goblin

#endif
