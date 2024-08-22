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
    };
}

#endif
