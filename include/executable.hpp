#ifndef LOADER_HPP
#define LOADER_HPP

#include "loadable.hpp"

#include <elf.h>

namespace Goblin {
    class Executable final : public Loadable{
    public:
        Executable(std::string file_path);
        ~Executable(void);
        void run(void);
    };
}

#endif
