#ifndef LOADER_HPP
#define LOADER_HPP

#include "loadable.hpp"

#include <elf.h>

namespace Roee_ELF {
    struct loader_segment {
        Elf64_Addr org_start_addr;
        Elf64_Xword org_end_addr;
        uint8_t mmap_perms;
    };

    class Executable final : public Loadable{
    public:
        Executable(const char* file_path);
        ~Executable(void);
        void run(void);

    private:
        static void remap_loader_segments(void);
        static uint8_t proc_maps_perms_to_mmap_perms(const char str_perms[4]);
    };
}

#endif
