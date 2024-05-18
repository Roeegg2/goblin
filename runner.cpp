#include <iostream>
#include <sys/mman.h>
#include <errno.h>
#include <cstring>

#include "runner.hpp"

namespace Roee_ELF {
    Runner::Runner(Parser_64b* const parser) : parser(parser) {}

    void Runner::run() {

        // // setting up the data data
        // uint64_t virtual_addr, size_in_mem;
        // uint64_t* data_buff = new uint64_t[0xe];
        // uint64_t* code = parser->get_code();

        // parser->get_data_info(&virtual_addr, &size_in_mem, &data_buff);
        // // NOTE not sure if i should use size_in_mem or size_in_file here
        // void* mapped_addr = mmap((void*)(virtual_addr), size_in_mem, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        // if (mapped_addr == MAP_FAILED) {
        //     std::cerr << "mmap failed: error " << errno << std::endl;
        //     return;
        // }
        // memcpy(mapped_addr, data_buff, 0xe);

        // // getting actual code binary

        // uint64_t foo = ((uint64_t)code) & (~0xfff);
        // if (mprotect((void*)(foo), sizeof(code), PROT_EXEC | PROT_READ) == -1) {
        //     std::cerr << "mprotect failed: error " << errno << std::endl;
        //     return;
        // }

        // running the code
        map_segments();

        void (*f)(void) = reinterpret_cast<void(*)()>(loaded_segments[code_segment_i].data_buff);
        f();
    }

    void Runner::map_segments() {
        loaded_segments.resize(parser->prog_headers.size());

        for (uint16_t i = 0; i < parser->prog_headers.size(); ++i) {
            if (parser->prog_headers[i].flags[0] == 'r' && parser->prog_headers[i].flags[1] == 'w' && parser->prog_headers[i].flags[2] == '.') { // if this is the segment containing the data section
                void* mapped_addr = mmap((void*)(parser->prog_headers[i].virtual_addr), parser->prog_headers[i].size_in_mem, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

                parser->file.seekg(parser->prog_headers[i].offset, std::ios::beg);
                parser->file.read((char*)(mapped_addr), parser->prog_headers[i].size_in_file);
            } else {
                loaded_segments[i].data_buff = new uint64_t[parser->prog_headers[i].size_in_file];

                parser->file.seekg(parser->prog_headers[i].offset, std::ios::beg);
                parser->file.read((char*)(loaded_segments[i].data_buff), parser->prog_headers[i].size_in_file);

                if (parser->prog_headers[i].flags[2] == 'x') {
                    code_segment_i = i; // WHY WHEN MOVING THIS TO THE END OF THE IF THEN THE PROGRAM GETS SEGFAULT??
                    uint64_t foo = ((uint64_t)loaded_segments[i].data_buff) & (~0xfff);

                    if (mprotect((void*)(foo), parser->prog_headers[i].size_in_mem * 8, PROT_EXEC | PROT_READ) == -1) {
                        std::cerr << "mprotect failed: error " << errno << std::endl;
                        return;
                    }
                }
            }
        }

    }

        /**
         * plan for mapping segments:
         * 1.
        */
}