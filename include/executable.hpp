#ifndef LOADER_HPP
#define LOADER_HPP

#include "loadable.hpp"

#include <elf.h>

namespace Roee_ELF {
    class Executable final : public Loadable{
    public:
        Executable(const char* file_path);
        ~Executable(void);
        void run(void);

    private:
        void apply_dyn_relocations(void);
        void map_symbols_from_external_lib(Elf64_Sym* dyn_sym);
        void link_external_libs(void);

        void resolve_symbols_from_external_lib(Elf64_Sym* lib_dyn_sym, const char* lib_dyn_str, const Elf64_Addr lib_base_addr);

    };
}

#endif
