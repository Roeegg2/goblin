#include "../include/loadable.hpp"
#include "../include/utils.hpp"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <iostream>
#include <memory>
#include <sys/mman.h>
#include <unistd.h>

#include <chrono>

extern "C" {
char **environ;
};

namespace Goblin {
const char *Loadable::s_DEFAULT_SHARED_OBJ_PATHS[]{
    "/lib/",
    "/usr/lib/",
    "/lib64/",
    "/usr/lib64/",
};

struct tls Loadable::s_tls;

Loadable::Loadable(const std::string file_path, const Elf64_Word module_id, const options_t options, const bool im_glibc)
    : ELF_File(file_path), m_im_glibc(im_glibc), m_options(options), m_dyn_seg_index(-1), m_tls_seg_index(-1), m_module_id(module_id),
      m_rpath(nullptr), m_runpath(nullptr), m_dyn({{0, 0}, {0, 0}, 0, 0}), m_plt({{0, 0}, 0}) {

    full_parse();
	dynsym_index = get_sect_indice(SHT_DYNSYM);
    m_segment_data.reserve(m_elf_header.e_phnum);
}

Loadable::~Loadable(void) {
    /*for (int i = 0; i < m_elf_header.e_phnum; i++) { // unmap all segments*/
    /*    if (m_segment_data[i] != nullptr) {*/
    /*        munmap(m_segment_data[i], m_prog_headers[i].p_memsz);*/
    /*    }*/
    /*}*/
}

void Loadable::parse_dyn_segment(std::set<Elf64_Xword> &m_dt_needed_syms) {
    Elf64_Dyn *dyn_table = reinterpret_cast<Elf64_Dyn *>(m_segment_data[m_dyn_seg_index]);
    while (dyn_table->d_tag != DT_NULL) {
        switch (dyn_table->d_tag) {
        case DT_RELA: // m_dyn rela table
            m_dyn.rela.m_addr = reinterpret_cast<Elf64_Rela *>(dyn_table->d_un.d_ptr + m_load_base_addr);
            break;
        case DT_JMPREL: // PLT relocation table
            m_plt.rela.m_addr = reinterpret_cast<Elf64_Rela *>(dyn_table->d_un.d_ptr + m_load_base_addr);
            break;
        case DT_SYMTAB: // m_dyn symbol table
            m_dyn.sym_table = reinterpret_cast<Elf64_Sym *>(dyn_table->d_un.d_ptr + m_load_base_addr);
            break;
        case DT_STRTAB: // m_dyn string table
            m_dyn.str_table = reinterpret_cast<char *>(dyn_table->d_un.d_ptr + m_load_base_addr);
            break;
        case DT_RELASZ: // m_dyn rela table total size
            m_dyn.rela.m_total_size = dyn_table->d_un.d_val;
            break;
        case DT_PLTRELSZ: // PLT relocation table total size
            m_plt.rela.m_total_size = dyn_table->d_un.d_val;
            break;
        case DT_PLTGOT: // m_plt.got address
            m_plt.got = reinterpret_cast<Elf64_Addr *>(dyn_table->d_un.d_ptr + m_load_base_addr);
            break;
        case DT_NEEDED: // name of a shared object we need to load
            m_dt_needed_syms.insert(dyn_table->d_un.d_val);
            break;
        case DT_RPATH:
            m_rpath = reinterpret_cast<char *>(dyn_table->d_un.d_val);
            break;
        case DT_RUNPATH:
            m_runpath = reinterpret_cast<char *>(dyn_table->d_un.d_val);
            break;
        case DT_RELR:
            m_dyn.relr.m_addr = reinterpret_cast<Elf64_Relr *>(dyn_table->d_un.d_ptr + m_load_base_addr);
            break;
        case DT_RELRSZ:
            m_dyn.relr.m_total_size = dyn_table->d_un.d_val;
            break;
        }
        dyn_table++;
    }

    // doing this later because we need to get m_dyn.str_table first
    if (m_rpath != nullptr) {
        m_rpath = reinterpret_cast<Elf64_Addr>(m_dyn.str_table) + m_rpath; // adding the offset (current value of
                                                                           // m_rpath) with the dynstr table
    }
    if (m_runpath != nullptr) {
        m_runpath = reinterpret_cast<Elf64_Addr>(m_dyn.str_table) + m_runpath; // adding the offset (current value of
                                                                               // m_runpath) with the dynstr table
    }
}

void Loadable::construct_loadeables_for_shared_objects(const std::set<Elf64_Xword> &m_dt_needed_syms) {
    for (Elf64_Xword dt_needed : m_dt_needed_syms) { // for each SO
        std::string path;
        if (resolve_path_rpath_runpath(m_rpath, path, m_dyn.str_table + dt_needed) ||
            resolve_path_rpath_runpath(m_runpath, path, m_dyn.str_table + dt_needed) ||
            resolve_path_ld_library_path(path, m_dyn.str_table + dt_needed) || resolve_path_default(path, m_dyn.str_table + dt_needed)) {
#ifdef INFO
            std::cout << "Loading shared object \"" << path << "\" and assigning module ID" << m_module_id + 1 << " \n";
#endif
            m_dependencies.insert(std::make_shared<Loadable>(path.c_str(), m_module_id + 1, m_options,
                                                             std::strncmp(m_dyn.str_table + dt_needed, "libc.so", 6) == 0));
            continue;
        }

        std::cerr << "Failed to resolve path for shared object: " << m_dyn.str_table + dt_needed << "\n";
        exit(1);
    }
}

bool Loadable::resolve_path_rpath_runpath(const char *r_run_path, std::string &path, const char *shared_obj_name) const {
    if ((r_run_path != nullptr) && (std::strcmp(r_run_path, "$ORIGIN") == 0)) {
        if (find_file(m_elf_file_path.parent_path(), shared_obj_name, path)) {
            return true;
        }
    }

    return false;
}

bool Loadable::resolve_path_ld_library_path(std::string &path, const char *shared_obj_name) {
    char *ld_library_path;
    if (((ld_library_path = getenv("LD_LIBRARY_PATH")) == NULL) || (ld_library_path[0] == '\0')) {
        return false;
    }

    return find_file(ld_library_path, shared_obj_name, path);
}

bool Loadable::resolve_path_default(std::string &path, const char *shared_obj_name) {
    for (const char *default_dir : s_DEFAULT_SHARED_OBJ_PATHS) {
        if (find_file(default_dir, shared_obj_name, path)) {
            return true;
        }
    }

    return false;
}

int Loadable::elf_perm_to_mmap_perms(const uint32_t elf_flags) {
    int mmap_flags = 0;

    if (elf_flags & 0x1)
        mmap_flags |= PROT_EXEC;
    if (elf_flags & 0x2)
        mmap_flags |= PROT_WRITE;
    if (elf_flags & 0x4)
        mmap_flags |= PROT_READ;

    return mmap_flags;
}

uint32_t Loadable::get_total_page_count(void) const {
    uint32_t total_page_count = 0;
    for (int8_t i = 0; i < m_elf_header.e_phnum; i++) {
        if ((m_prog_headers[i].p_type == PT_LOAD) && m_prog_headers[i].p_memsz > 0) {
            total_page_count += get_page_count(m_prog_headers[i].p_memsz, m_prog_headers[i].p_vaddr);
        }
    }

    return total_page_count;
}

void Loadable::alloc_mem_for_segments(void) {
    m_load_base_addr = m_prog_headers[0].p_vaddr; // 0 for PIE, actual base address for non-PIE. that way
                                                  // mmap will allocate memory at the correct address (0
                                                  // means kernel will choose the address for us)

    uint32_t total_page_count = get_total_page_count();
    m_load_base_addr = reinterpret_cast<Elf64_Addr>(mmap(reinterpret_cast<void *>(m_load_base_addr), total_page_count * PAGE_SIZE,
                                                         PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));

    if (reinterpret_cast<void *>(m_load_base_addr) == MAP_FAILED) {
        std::cerr << "mmap failed\n";
        exit(1);
    }

    if (m_elf_header.e_type == ET_EXEC)
        m_load_base_addr = 0x0;
}

void Loadable::setup_segment(const Elf64_Word i) {
    m_segment_data[i] = reinterpret_cast<void *>(m_prog_headers[i].p_vaddr + m_load_base_addr); // mmap assigns only page aligned addresses,
                                                                                                // and we need to know the exact address
    m_elf_file.seekg(m_prog_headers[i].p_offset);
    m_elf_file.read(reinterpret_cast<char *>(m_segment_data[i]),
                    m_prog_headers[i].p_filesz); // read data from file to memory

    // As specified in the System V ABI, all data not mapped from file should be
    // zeroed out
    if (m_prog_headers[i].p_filesz < m_prog_headers[i].p_memsz) {
        memset(reinterpret_cast<void *>(m_prog_headers[i].p_vaddr + m_load_base_addr + m_prog_headers[i].p_filesz), 0,
               m_prog_headers[i].p_memsz - m_prog_headers[i].p_filesz);
    }
}

void Loadable::map_segments(void) {
    alloc_mem_for_segments();

    for (int8_t i = 0; i < m_elf_header.e_phnum; i++) {
        if (m_prog_headers[i].p_memsz <= 0) {
            continue;
        }

        switch (m_prog_headers[i].p_type) {
        case PT_TLS:
            m_tls_seg_index = i;
            s_tls.m_init_imgs.push_back({.m_module_id = m_module_id, // FIXME: might need to change this if
                                                                     // there are cases where the module ID is
                                                                     // decided upon at compile/linktime
                                         .m_size = m_prog_headers[i].p_memsz,
                                         .m_data = m_segment_data[i],
                                         .m_tlsoffset = s_tls.m_total_imgs_size,
                                         .m_is_static_model = true});
            s_tls.m_total_imgs_size += m_prog_headers[i].p_memsz;
            break;
        case PT_DYNAMIC:
            m_dyn_seg_index = i;
            break;
        case PT_GNU_RELRO:
            break;
        case PT_LOAD:
            break;
        default: // nothing to do, so go next
            continue;
        }

        setup_segment(i);
    }
}

void Loadable::set_correct_permissions(void) {
    for (int8_t i = 0; i < m_elf_header.e_phnum; i++) {
        if (((m_prog_headers[i].p_type == PT_LOAD) && (m_prog_headers[i].p_memsz > 0)) || (m_prog_headers[i].p_type == PT_GNU_RELRO) ||
            (m_prog_headers[i].p_type == PT_TLS)) {
            if (m_prog_headers[i].p_memsz > 0) {
                const uint16_t page_count = get_page_count(m_prog_headers[i].p_memsz, m_prog_headers[i].p_vaddr);

                if (mprotect(reinterpret_cast<void *>(page_align_down(reinterpret_cast<Elf64_Addr>(m_segment_data[i]))),
                             page_count * PAGE_SIZE, elf_perm_to_mmap_perms(m_prog_headers[i].p_flags)) == -1) {
                    std::cerr << "mprotect failed\n";
                    exit(1);
                }
            }
        }
    }
}

void Loadable::init_extern_relas(void) {
    auto construct_name_copy = [](const char *str_table, const Elf64_Word sym_name) { return std::string(str_table + sym_name); };
    auto construct_name_jumps_globd = [](const char *str_table, const Elf64_Word sym_name) {
        std::string ret = str_table + sym_name;
        const size_t pos = ret.find('@');
        if (pos != std::string::npos) {
            ret.insert(pos, 1, '@');
        }
        return ret;
    };
    auto apply_relocation_copy = [](Loadable *self, const std::shared_ptr<Loadable> &dep, const Elf64_Word sym_index, const uint32_t i) {
        char *src = reinterpret_cast<char *>(self->m_dyn.sym_table[sym_index].st_value + self->m_load_base_addr);
        const char *dst = reinterpret_cast<const char *>(dep->m_dyn.sym_table[i].st_value + dep->m_load_base_addr);
        std::strcpy(src, dst);
    };
    auto apply_relocation_jumps_globd = [](Loadable *self, const std::shared_ptr<Loadable> &dep, const Elf64_Word sym_index,
                                           const uint32_t i) {
        Elf64_Addr *addr = reinterpret_cast<Elf64_Addr *>(self->m_dyn.rela.m_addr[sym_index].r_offset + self->m_load_base_addr);
        *addr = dep->m_dyn.sym_table[i].st_value + dep->m_load_base_addr + dep->m_dyn.rela.m_addr[i].r_addend;
    };

    m_extern_relas[ExternRelasIndices::REL_COPY].f_construct_name = construct_name_copy;
    m_extern_relas[ExternRelasIndices::REL_COPY].f_apply_relocation = apply_relocation_copy;
    m_extern_relas[ExternRelasIndices::REL_JUMPS_GLOBD].f_construct_name = construct_name_jumps_globd;
    m_extern_relas[ExternRelasIndices::REL_JUMPS_GLOBD].f_apply_relocation = apply_relocation_jumps_globd;
}

void Loadable::build_shared_objs_tree(void) {
    map_segments();
    if (m_dyn_seg_index >= 0) {
        std::set<Elf64_Xword> m_dt_needed_syms;
        parse_dyn_segment(m_dt_needed_syms);
        construct_loadeables_for_shared_objects(m_dt_needed_syms); // for each shared object dependency, create a
                                                                   // Loadable object
    }

    apply_dyn_rela_relocations();
    apply_dyn_relr_relocations();
    apply_plt_rela_relocations();

    init_extern_relas();
    for (auto &dep : m_dependencies) { // for every shared object dependency
        dep->build_shared_objs_tree(); // recursively build the shared objects
                                       // tree
        apply_external_dyn_relocations(dep);
    }
    apply_tls_relocations();

    set_correct_permissions(); // set the correct permissions for the segments
}

/* for anyone reading this in the future, I'm very sorry for this
 * mess...Hopefully you pull through :) */
void Loadable::apply_external_dyn_relocations(const std::shared_ptr<Loadable> dep) {
    auto start = std::chrono::high_resolution_clock::now();
    /*const auto dynsym_index = get_sect_indice(SHT_DYNSYM);*/
    const auto dep_entnum = dep->m_sect_headers[dep->dynsym_index].sh_size / dep->m_sect_headers[dep->dynsym_index].sh_entsize;

    for (auto extern_rela : m_extern_relas) {       // for every set of symbols that need relocation
        for (auto sym_index : extern_rela.m_syms) { // for every needed symbol
            std::string org_sym_name = extern_rela.f_construct_name(m_dyn.str_table,
                                                                    m_dyn.sym_table[sym_index].st_name); // get name of the symbol
            for (uint32_t i = 0; i < dep_entnum; i++) { // for every symbol in the dependency 
                std::string dep_sym_name = dep->m_dyn.str_table + dep->m_dyn.sym_table[i].st_name;
                if (dep_sym_name == org_sym_name) {                          // if this is the sym we're looking for
                    extern_rela.f_apply_relocation(this, dep, sym_index, i); // apply the relocation
                    break;
                }
            }
        }
    }
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;
    std::cout << "Time taken: " << duration.count() << " seconds" << std::endl;
}

void Loadable::apply_tls_relocations(void) {
    for (auto i : m_tls_relas) {
        Elf64_Addr *addr = reinterpret_cast<Elf64_Addr *>(m_dyn.rela.m_addr[i].r_offset + m_load_base_addr);
        Elf64_Sym *sym = reinterpret_cast<Elf64_Sym *>(m_dyn.sym_table + ELF64_R_SYM(m_dyn.rela.m_addr[i].r_info));
        switch (ELF64_R_TYPE(m_dyn.rela.m_addr[i].r_info)) {
        case R_X86_64_DTPOFF64:
            *addr = sym->st_value + m_load_base_addr;
            break;
        case R_X86_64_DTPMOD64:
            *addr = m_module_id;
            break;
        default: /*case of R_X86_64_TPOFF64*/
            *addr = sym->st_value + m_dyn.rela.m_addr[i].r_addend + m_load_base_addr;
            break;
        }
    }
}

void Loadable::apply_plt_rela_relocations(void) {
    if (m_plt.rela.m_addr == nullptr) {
        return;
    }

    if (__builtin_expect(m_options.binding == BINDING_LAZY, 1)) {
        return;
    } else { // eager binding
        for (Elf64_Word i = 0; i < (m_plt.rela.m_total_size / m_plt.rela.s_ENTRY_SIZE); i++) {
            Elf64_Addr *addr = reinterpret_cast<Elf64_Addr *>(m_plt.rela.m_addr[i].r_offset + m_load_base_addr);
            /*Elf64_Sym *sym = reinterpret_cast<Elf64_Sym *>(m_plt.sym_table + ELF64_R_SYM(m_dyn.rela.m_addr[i].r_info));*/

            switch (ELF64_R_TYPE(m_plt.rela.m_addr[i].r_info)) {
            case R_X86_64_JUMP_SLOT:
            case R_X86_64_GLOB_DAT: // simply copy the value of the symbol to
                                    // the address
                m_extern_relas[ExternRelasIndices::REL_JUMPS_GLOBD].m_syms.insert(ELF64_R_SYM(m_dyn.rela.m_addr[i].r_info));
                break;
            case R_X86_64_IRELATIVE: // interpret rela.addr[i].r_addend +
                                     /*if (!m_im_glibc) {*/
                *addr =
                    reinterpret_cast<Elf64_Addr>(reinterpret_cast<Elf64_Addr *(*)()>(m_plt.rela.m_addr[i].r_addend + m_load_base_addr)());
                /*}*/
                break;
            default:
                std::cerr << "PLT Unknown relocation type: " << std::dec << ELF64_R_TYPE(m_plt.rela.m_addr[i].r_info) << "\n";
                exit(1);
            }
        }
    }
}

/*relatively new feature added to ELF*/
void Loadable::apply_dyn_relr_relocations(void) {
    if (m_dyn.relr.m_addr == nullptr) {
        return;
    }

    for (Elf64_Word i = 0; i < (m_dyn.relr.m_total_size / m_dyn.relr.s_ENTRY_SIZE); i++) {
        m_dyn.relr.m_addr[i] += m_load_base_addr;
    }
}

void Loadable::apply_dyn_rela_relocations(void) {
    if (m_dyn.rela.m_addr == nullptr) {
        return;
    }

    for (Elf64_Word i = 0; i < (m_dyn.rela.m_total_size / m_dyn.rela.s_ENTRY_SIZE); i++) {
        Elf64_Addr *addr = reinterpret_cast<Elf64_Addr *>(m_dyn.rela.m_addr[i].r_offset + m_load_base_addr);
        Elf64_Sym *sym = reinterpret_cast<Elf64_Sym *>(m_dyn.sym_table + ELF64_R_SYM(m_dyn.rela.m_addr[i].r_info));

        switch (ELF64_R_TYPE(m_dyn.rela.m_addr[i].r_info)) {
        case R_X86_64_RELATIVE:
            *addr = m_dyn.rela.m_addr[i].r_addend + m_load_base_addr;
            break;
        case R_X86_64_64:
            *addr = m_dyn.rela.m_addr[i].r_addend + sym->st_value + m_load_base_addr;
            break;
        case R_X86_64_COPY: // advacned relocation type (data is needed from
                            // external object)
            m_extern_relas[ExternRelasIndices::REL_COPY].m_syms.insert(ELF64_R_SYM(m_dyn.rela.m_addr[i].r_info));
            break;
        case R_X86_64_IRELATIVE: // interpret rela.addr[i].r_addend +
            if (!m_im_glibc) {
                *addr =
                    reinterpret_cast<Elf64_Addr>(reinterpret_cast<Elf64_Addr *(*)()>(m_dyn.rela.m_addr[i].r_addend + m_load_base_addr)());
            }
            break;
        case R_X86_64_GLOB_DAT: // simply copy the value of the symbol to the
                                // address
            m_extern_relas[ExternRelasIndices::REL_JUMPS_GLOBD].m_syms.insert(ELF64_R_SYM(m_dyn.rela.m_addr[i].r_info));
            break;
        case R_X86_64_DTPOFF64:
        case R_X86_64_DTPMOD64:
        case R_X86_64_TPOFF64:
            m_tls_relas.insert(i);
            break;
        default:
            std::cerr << "Unknown relocation type: " << std::dec << ELF64_R_TYPE(m_dyn.rela.m_addr[i].r_info) << "\n";
            exit(1);
        }
    }
}
}; // namespace Goblin
   /*
       get indices of sections (symtab, strtab, gnu.hash, .hash)
       if (there is a gnu.hash)
           use gnu.hash
       else if (there is a .hash)
           use .hash
       else
           use symtab
   
   */
