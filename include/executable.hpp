#ifndef LOADER_HPP
#define LOADER_HPP

#include "loadable.hpp"

#include <elf.h>

namespace Goblin {
    struct loader_segment {
        Elf64_Addr org_start_addr;
        Elf64_Xword org_end_addr;
        uint8_t mmap_perms;
    };

    class Executable final : public Loadable{
    public:
        Executable(std::string file_path);
        ~Executable(void);
        void run(void);
    protected:
        void patch_libc();
    };
}

#endif
