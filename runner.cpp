#include "runner.hpp"

namespace Roee_ELF {
    Runner::Runner(Parser_64b* const parser) : parser(parser) {}

    void Runner::run(void) {
        void (*start_execution)(void) = reinterpret_cast<void(*)()>(parser->elf_header.entry_point); // turn the code segment start into a function ptr
        start_execution(); // execute the code
    }
}