#include <iostream>
#include <sys/mman.h>
#include <errno.h>

#include "runner.hpp"

namespace Roee_ELF {
    Runner::Runner(Parser_64b* const parser) : parser(parser) {}

    void Runner::run() const {
        uint64_t* code = parser->get_code();

        uint64_t foo = ((uint64_t)code) & (~0xfff);
        if (mprotect((void*)(foo), 0x100, PROT_EXEC | PROT_READ) == -1) {
            std::cerr << "mprotect failed: error " << errno << std::endl;
            return;
        }

        void (*f)(void) = reinterpret_cast<void(*)()>(code);
        f();
    }
}