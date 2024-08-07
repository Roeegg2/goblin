#include "../include/runner.hpp"

namespace Roee_ELF {
    Runner::Runner(Parser_64b* const parser) : parser(parser) {
        init(parser);
    }

    void Runner::init(Parser_64b* const parser) {
        this->parser = parser;
    }

    void Runner::run(void) { //parser->elf_header.entry_point 0x401655
        void (*start_execution)(void) = reinterpret_cast<void(*)()>(0x401655); // turn the code segment start into a function ptr
        start_execution(); // execute the code
    }
}
