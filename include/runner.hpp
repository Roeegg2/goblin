#ifndef LOADER_HPP
#define LOADER_HPP

#include "loader.hpp"

namespace Roee_ELF {
    class Runner final : public Loader{
    public:
        Runner(const char* file_path);
        ~Runner(void);
        void run(void);

    private:
        void apply_dyn_relocations(void);
        void link_external_libs(void);
    };
}

#endif
