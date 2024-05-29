#include <iostream>
#include <sys/mman.h>
#include <errno.h>
#include <cstring>

#include "runner.hpp"

#define DOES_CONTAIN_CODE_SECTION (parser->prog_headers[i].flags & 0x1)
#define DOES_CONTAIN_DATA_SECTION (parser->prog_headers[i].flags & 0x2) && (parser->prog_headers[i].flags & 0x4)
namespace Roee_ELF {
    Runner::Runner(Parser_64b* const parser) : parser(parser) {}

    void Runner::run() {
        map_segments();

        void (*start_execution)(void) = reinterpret_cast<void(*)()>(loaded_segments[code_segment_i].buff); // turn the code segment start into a function ptr
        start_execution(); // execute the code
    }

    void Runner::map_segments() {
        loaded_segments.resize(parser->prog_headers.size());

        for (uint16_t i = 0; i < parser->prog_headers.size(); ++i) {
            if ((parser->prog_headers[i].flags & 0x2) && (parser->prog_headers[i].flags & 0x4) && (!(parser->prog_headers[i].flags & 0x1))) {
                void* mapped_addr = mmap((void*)(parser->prog_headers[i].v_addr), parser->prog_headers[i].size_in_mem, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                if (mapped_addr == MAP_FAILED) {
                    std::cerr << "mmap failed: error " << errno << std::endl;
                    return;
                }

                parser->get_segment_data((uint64_t*)mapped_addr, i);

            } else {
                loaded_segments[i].buff = new uint64_t[parser->prog_headers[i].size_in_mem];
                parser->get_segment_data(loaded_segments[i].buff, i);

                if ((parser->prog_headers[i].flags & 0x1)) {
                    code_segment_i = i;
                    uint64_t foo = ((uint64_t)loaded_segments[i].buff) & (~0xfff);

                    if (mprotect((void*)foo, parser->prog_headers[i].size_in_mem * 8, PROT_EXEC | PROT_READ) == -1) {
                        std::cerr << "mprotect failed: error " << errno << std::endl;
                        return;
                    }
                }
            }
        }
    }
}