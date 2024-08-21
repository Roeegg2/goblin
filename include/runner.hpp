#ifndef LOADER_HPP
#define LOADER_HPP

#include "loader.hpp"
#include <elf.h>

namespace Roee_ELF {
    class Runner final : public Loader{
    public:
        Runner(const char* file_path);
        ~Runner(void);
        void run(void);

    private:
        void apply_dyn_relocations(void);
        void map_symbols_from_external_lib(Elf64_Sym* dyn_sym);
        void link_external_libs(void);

        void resolve_symbols_from_external_lib(Elf64_Sym* lib_dyn_sym, const char* lib_dyn_str, const Elf64_Addr lib_base_addr);

    private:
        std::list<Elf64_Word> needed_symbols; // indices of symbols that are needed from external libraries
    };
}

#endif
