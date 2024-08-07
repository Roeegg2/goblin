#include "../include/runner.hpp"
#include "../include/syscalls.hpp"
#include "../include/utils.hpp"

#include <sys/mman.h>

namespace Roee_ELF {
    Runner::Runner(Parser_64b* const parser) : parser(parser) {
        init(parser);
    }

    void Runner::init(Parser_64b* const parser) {
        this->parser = parser;
    }

    void Runner::map_segment_data_to_mem(const u8 i) {
        parser->prog_headers[i].data = reinterpret_cast<void*>(syscall_mmap(
            parser->prog_headers[i].v_addr,
            parser->prog_headers[i].size_in_mem,
            elf_perm_to_mmap_perms(parser->prog_headers[i].flags),
            MAP_PRIVATE | MAP_FIXED_NOREPLACE,
            parser->fd,
            parser->prog_headers[i].offset
        ));

        if (parser->prog_headers[i].data == MAP_FAILED) {
            print_str_literal(STDERR_FD, "mmap failed\n");
            syscall_exit(1);
        }

        // if size_in_mem is bigger than size_in_file, the rest of the segments memory should be filled with 0's
        memset(
            reinterpret_cast<void*>(reinterpret_cast<u8*>(parser->prog_headers[i].data) + parser->prog_headers[i].size_in_file),
            NULL,
            parser->prog_headers[i].size_in_mem - parser->prog_headers[i].size_in_file);

    }

    void Runner::run(void) { //parser->elf_header.entry_point 0x401655
        switch (syscall_fork()) {
            case -1:
                print_str_literal(STDOUT_FD, "fork failed\n");
                syscall_exit(1);
                break;
            case 0:
#ifdef DEBUG
                print_str_literal(STDOUT_FD, "Starting execution...\n");
#endif
                for (u8 i = 0; i < parser->ph_data.entry_count; i++) { // map the segments to memory
                    map_segment_data_to_mem(i);
                }
                start_execution = reinterpret_cast<void(*)()>(parser->elf_header.entry_point); // turn the code segment start into a function ptr
                start_execution(); // execute executable code
                break;
            default:
                syscall_exit(0);
        }
    }
}
