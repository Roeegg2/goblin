#include "../include/loadable.hpp"

#include <cerrno>
#include <cstdint>
#include <elf.h>
#include <fcntl.h>
#include <memory>
#include <sys/mman.h>
#include <unistd.h>
#include <iostream>
#include <cstring>

extern "C" {
    char** environ;
    extern void _my_dl_open(void);
    extern void _my_exit();
};

namespace Goblin {
    const char* Loadable::DEFAULT_SHARED_OBJ_PATHS[] {
        "/lib/",
        "/usr/lib/",
        "/lib64/",
        "/usr/lib64/",
    };

    Loadable::Loadable(std::string file_path)
        : ELF_File(file_path), dyn_seg_index(-1), tls_seg_index(-1),
        rpath(nullptr), runpath(nullptr), dyn({{0, 0}, 0, 0}), plt({{0, 0}, 0}) {

        full_parse();
        segment_data.reserve(elf_header.e_phnum);
    }

    Loadable::~Loadable(void){
        for (int i = 0; i < elf_header.e_phnum; i++) { // unmap all segments
            if (segment_data[i] != nullptr) {
                munmap(segment_data[i], prog_headers[i].p_memsz);
            }
        }
    }

    bool find_file(const std::filesystem::path& directory, const std::string& filename, std::string& found_path) {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(directory)) {
            if (entry.is_regular_file() && entry.path().filename() == filename) {
                found_path = entry.path().string();
                return true;
            }
        }
        return false;
    }

    void Loadable::parse_dyn_segment(void) {
        Elf64_Dyn* dyn_table = reinterpret_cast<Elf64_Dyn*>(segment_data[dyn_seg_index]);
        while (dyn_table->d_tag != DT_NULL) {
            switch (dyn_table->d_tag) {
            case DT_RELA: // dyn rela table
                dyn.rela.addr = reinterpret_cast<Elf64_Rela*>(dyn_table->d_un.d_ptr + load_base_addr);
                break;
            case DT_JMPREL: // PLT relocation table
                plt.rela.addr = reinterpret_cast<Elf64_Rela*>(dyn_table->d_un.d_ptr + load_base_addr);
                break;
            case DT_SYMTAB: // dyn symbol table
                dyn.sym = reinterpret_cast<Elf64_Sym*>(dyn_table->d_un.d_ptr + load_base_addr);
                break;
            case DT_STRTAB: // dyn string table
                dyn.str = reinterpret_cast<char*>(dyn_table->d_un.d_ptr + load_base_addr);
                break;
            case DT_RELASZ: // dyn rela table total size
                dyn.rela.total_size = dyn_table->d_un.d_val;
                break;
            case DT_PLTRELSZ: // PLT relocation table total size
                plt.rela.total_size = dyn_table->d_un.d_val;
                break;
            case DT_PLTGOT: // plt.got address
                plt.got = reinterpret_cast<Elf64_Addr*>(dyn_table->d_un.d_ptr + load_base_addr);
                break;
            case DT_NEEDED: // name of a shared object we need to load
                dt_needed_list.insert(dyn_table->d_un.d_val);
                break;
            case DT_RPATH:
                rpath = reinterpret_cast<char*>(dyn_table->d_un.d_val);
                break;
            case DT_RUNPATH:
                runpath = reinterpret_cast<char*>(dyn_table->d_un.d_val);
                break;
            }
            dyn_table++;
        }

        // doing this later because we need to get dyn.str first
        if (rpath != nullptr) {
            rpath = reinterpret_cast<Elf64_Addr>(dyn.str) + rpath; // adding the offset (current value of rpath) with the dynstr table
        }
        if (runpath != nullptr) {
            runpath = reinterpret_cast<Elf64_Addr>(dyn.str) + runpath; // adding the offset (current value of runpath) with the dynstr table
        }
    }

    void Loadable::construct_loadeables_for_shared_objects(void) {
        for (Elf64_Xword dt_needed : dt_needed_list) { // for each SO
            std::string path;
            if (std::strcmp(dyn.str + dt_needed, "ld-linux-x86-64.so.2") == 0) {
#ifdef INFO
                std::cout << "Skipping ld-linux-x86-64.so.2...\n";
#endif
                continue;
            }
            if (resolve_path_rpath_runpath(rpath, path, dyn.str + dt_needed) ||
                resolve_path_rpath_runpath(runpath, path, dyn.str + dt_needed) ||
                resolve_path_ld_library_path(path, dyn.str + dt_needed) ||
                resolve_path_default(path, dyn.str + dt_needed)) {
#ifdef INFO
                std::cout << "Loading shared object \"" << path << "\"\n";
#endif
                dependencies.insert(std::make_shared<Loadable>(path.c_str()));
                continue;
            }

            std::cerr << "Failed to resolve path for shared object: " << dyn.str + dt_needed << "\n";
            exit(1);
        }

        dt_needed_list.clear();
    }

    bool Loadable::resolve_path_rpath_runpath(const char* r_run_path, std::string& path, const char* shared_obj_name) const {
        if ((r_run_path != nullptr) && (std::strcmp(r_run_path, "$ORIGIN") == 0)) {
            if (find_file(elf_file_path.parent_path(), shared_obj_name, path)) {
                return true;
            }
        }

        return false;
    }

    bool Loadable::resolve_path_ld_library_path(std::string& path, const char* shared_obj_name) {
        char* ld_library_path;
        if (((ld_library_path = getenv("LD_LIBRARY_PATH")) == NULL) || (ld_library_path[0] == '\0')) {
            return false;
        }

        return find_file(ld_library_path, shared_obj_name, path);
    }

    bool Loadable::resolve_path_default(std::string& path, const char* shared_obj_name) const {
        for (const char* default_dir : DEFAULT_SHARED_OBJ_PATHS) {
            if (find_file(default_dir, shared_obj_name, path)) {
                return true;
            }
        }

        return false;
    }

    uint32_t Loadable::get_page_count(Elf64_Xword memsz, Elf64_Addr addr) {
        return (memsz + (addr % PAGE_SIZE) + PAGE_SIZE - 1) / PAGE_SIZE;
    }

    int Loadable::elf_perm_to_mmap_perms(uint32_t const elf_flags) {
        int mmap_flags = 0;

        if (elf_flags & 0x1) mmap_flags |= PROT_EXEC;
        if (elf_flags & 0x2) mmap_flags |= PROT_WRITE;
        if (elf_flags & 0x4) mmap_flags |= PROT_READ;

        return mmap_flags;
    }

    uint32_t Loadable::get_total_page_count(void) {
        uint32_t total_page_count = 0;
        for (int8_t i = 0; i < elf_header.e_phnum; i++) {
            if (prog_headers[i].p_type == PT_LOAD && prog_headers[i].p_memsz > 0) {
                total_page_count += get_page_count(prog_headers[i].p_memsz, prog_headers[i].p_vaddr);
            }
        }

        return total_page_count;
    }

    void Loadable::alloc_mem_for_segments(void) {
        load_base_addr = prog_headers[0].p_vaddr;

        uint32_t total_page_count = get_total_page_count();
        load_base_addr = reinterpret_cast<Elf64_Addr>(mmap(reinterpret_cast<void*>(load_base_addr),
            total_page_count * PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));

        if (reinterpret_cast<void*>(load_base_addr) == MAP_FAILED) {
            if (errno == EADDRINUSE) {

            }
            else {
                std::cerr << "mmap failed\n";
                exit(1);
            }
        }

        if (elf_header.e_type == ET_EXEC)
            load_base_addr = 0x0;
    }

    void Loadable::map_segments(void) {
        alloc_mem_for_segments();

        for (int8_t i = 0; i < elf_header.e_phnum; i++) {
            if (prog_headers[i].p_memsz <= 0) {
                continue;
            }

            switch(prog_headers[i].p_type) {
            case PT_TLS:
                tls_seg_index = i; // save the index of TLS segment
                std::cout << "TLS segment found\n";
                __attribute__((fallthrough));
            case PT_LOAD:
                segment_data[i] = reinterpret_cast<void*>(prog_headers[i].p_vaddr + load_base_addr);
                break;
            case PT_DYNAMIC:
                dyn_seg_index = i; // save the index of the dynamic segment
                segment_data[i] = mmap(NULL, // allocate mem (we allocate independently of the PT_LOAD segments, since we don't care about the address it is mapped in - we just need the data)
                    get_page_count(prog_headers[i].p_memsz, prog_headers[i].p_vaddr) * PAGE_SIZE,
                    PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,-1, 0);
                break;
            default:
                continue;
            }

            elf_file.seekg(prog_headers[i].p_offset);
            elf_file.read(reinterpret_cast<char*>(segment_data[i]), prog_headers[i].p_filesz);

            // As specified in the System V ABI, all data not mapped from file should be zeroed out
            if (prog_headers[i].p_filesz < prog_headers[i].p_memsz) {
                memset(reinterpret_cast<void*>(prog_headers[i].p_vaddr + load_base_addr + prog_headers[i].p_filesz),
                    0, prog_headers[i].p_memsz - prog_headers[i].p_filesz);
            }
        }
    }

    void Loadable::set_correct_permissions(void) {
        for (int8_t i = 0; i < elf_header.e_phnum; i++) {
            if ((prog_headers[i].p_type == PT_LOAD) && (prog_headers[i].p_memsz > 0)) {
                const uint16_t page_count = get_page_count(prog_headers[i].p_memsz, prog_headers[i].p_vaddr);

                if (mprotect(reinterpret_cast<void*>(PAGE_ALIGN_DOWN(reinterpret_cast<Elf64_Addr>(segment_data[i]))),
                    page_count * PAGE_SIZE, elf_perm_to_mmap_perms(prog_headers[i].p_flags)) == -1) {
                    std::cerr << "mprotect failed\n";
                    exit(1);
                }
            }
        }
    }

    void Loadable::init_tls_segment(void) {

    }

    void Loadable::build_shared_objs_tree(void) {
        map_segments();
        if (dyn_seg_index >= 0){
            parse_dyn_segment();
        }
        construct_loadeables_for_shared_objects();
        apply_basic_dyn_relocations(dyn.rela);
        apply_basic_dyn_relocations(plt.rela); // NOTE if not doing lazy binding
        if (tls_seg_index >= 0) {
            init_tls_segment();
        }

        for (auto& dep : dependencies) { // for every shared object dependency
            dep->build_shared_objs_tree(); // recursively build the shared objects tree
            apply_dep_dyn_relocations(dep); // apply the dynamic relocations of the dependency
        }

        set_correct_permissions(); // set the correct permissions for the segments
    }

    void Loadable::apply_dep_dyn_relocations(std::shared_ptr<Loadable> dep) {
        Elf64_Sym* dep_dyn_sym = dep->dyn.sym + 1; // dont want to change the actual pointer | incrementing by one to skip the null
        do { // for every needed DYN symbols of the dependency
            std::string dep_sym_name = dep->dyn.str + dep_dyn_sym->st_name;
            for (auto sym : needed_symbols) { // for every needed DYN symbol
                std::string org_sym_name = dyn.str + dyn.sym[sym].st_name; // construct the corresponding symbol name to check
                if (dep_sym_name == org_sym_name) {
                    char* src = reinterpret_cast<char*>(dyn.sym[sym].st_value + load_base_addr);
                    const char* dst = reinterpret_cast<const char*>(dep_dyn_sym->st_value + dep->load_base_addr);
                    strcpy(src, dst);
                }
            }
            dep_dyn_sym += 1;
        } while (ELF64_ST_TYPE(dep->dyn.sym->st_info) != STT_NOTYPE);
    }

    void Loadable::apply_basic_dyn_relocations(const struct rela_table& rela) {
        if (rela.addr == nullptr){
            return;
        }

        for (Elf64_Word i = 0; i < (rela.total_size / rela.entry_size); i++) {
            Elf64_Addr* addr = reinterpret_cast<Elf64_Addr*>(rela.addr[i].r_offset + load_base_addr);
            Elf64_Sym* sym = reinterpret_cast<Elf64_Sym*>(dyn.sym + ELF64_R_SYM(rela.addr[i].r_info));
            switch (ELF64_R_TYPE(rela.addr[i].r_info)) {
                case R_X86_64_RELATIVE:
                    *addr = rela.addr[i].r_addend + load_base_addr;
                    break;
                case R_X86_64_64:
                    *addr = rela.addr[i].r_addend + load_base_addr + sym->st_value;
                    break;
                case R_X86_64_COPY: // advacned relocation type (data is needed from external object)
                    needed_symbols.insert(i);
                    // *addr = *reinterpret_cast<Elf64_Addr*>(dyn.rela.addr[i].r_addend + load_base_addr);
                    break;
                case R_X86_64_IRELATIVE: // interpret rela.addr[i].r_addend + load_base_addr as a function and call it. place the return value inside
                    *addr = reinterpret_cast<Elf64_Addr>(
                        reinterpret_cast<Elf64_Addr (*)()>(rela.addr[i].r_addend + load_base_addr)());
                    break;
                case R_X86_64_JUMP_SLOT:
                case R_X86_64_GLOB_DAT: // simply copy the value of the symbol to the address
                    *addr = sym->st_value + load_base_addr;
                    break;
                case R_X86_64_DTPMOD64:
                case R_X86_64_DTPOFF64:
                case R_X86_64_TPOFF64:
                case R_X86_64_TLSGD:
                case R_X86_64_TLSLD:
                case R_X86_64_DTPOFF32:
                case R_X86_64_GOTTPOFF:
                case R_X86_64_TPOFF32:
                case R_X86_64_TLSDESC_CALL:
                    break;
                default:
                    std::cerr << "Unknown relocation type: " << std::dec << ELF64_R_TYPE(rela.addr[i].r_info) << "\n";
                    exit(1);
            }
        }
    }
}

/*


*/
