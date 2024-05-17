#include <iostream>
#include <sys/mman.h>
#include <errno.h>
#include <cstring>

#include "runner.hpp"

namespace Roee_ELF {
    Runner::Runner(Parser_64b* const parser) : parser(parser) {}

    void Runner::run() const {

        // setting up the data data
        uint64_t virtual_addr, size_in_mem;
        uint64_t* data_buff = new uint64_t[0xe];
        uint64_t* code = parser->get_code();
        std::cout << "code addr: " << std::hex << code << "\n";
        std::cout << "data addr: " << std::hex << data_buff << "\n";
        parser->get_data_info(&virtual_addr, &size_in_mem, &data_buff);
        // NOTE not sure if i should use size_in_mem or size_in_file here
        void* mapped_addr = mmap((void*)(virtual_addr), size_in_mem, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mapped_addr == MAP_FAILED) {
            std::cerr << "mmap failed: error " << errno << std::endl;
            return;
        }
        memcpy(mapped_addr, data_buff, 0xe);

        // getting actual code binary

        uint64_t foo = ((uint64_t)code) & (~0xfff);
        if (mprotect((void*)(foo), sizeof(code), PROT_EXEC | PROT_READ) == -1) {
            std::cerr << "mprotect failed: error " << errno << std::endl;
            return;
        }

        // running the code
        void (*f)(void) = reinterpret_cast<void(*)()>(code);
        f();

        delete code;
    }
}