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

    void Runner::map_segment_data_to_mem(const uint8_t i) {
        segment_data = reinterpret_cast<void**>(syscall_mmap(
            NULL,
            sizeof(void*) * parser->elf_header.e_phnum,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0
        ));


        segment_data[i] = reinterpret_cast<void*>(syscall_mmap(
            parser->prog_headers[i].p_vaddr,
            parser->prog_headers[i].p_memsz,
            elf_perm_to_mmap_perms(parser->prog_headers[i].p_flags),
            MAP_PRIVATE | MAP_FIXED_NOREPLACE,
            parser->elf_file_fd,
            parser->prog_headers[i].p_offset
        ));

        if (segment_data[i] == MAP_FAILED) {
            print_str_literal(STDERR_FD, "mmap failed\n");
            syscall_exit(1);
        }

        // if size_in_mem is bigger than size_in_file, the rest of the segments memory should be filled with 0's
        memset(
            reinterpret_cast<void*>(reinterpret_cast<uint8_t*>(segment_data[i]) + parser->prog_headers[i].p_filesz),
            NULL,
            parser->prog_headers[i].p_memsz - parser->prog_headers[i].p_filesz);

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
                for (int8_t i = 0; i < parser->elf_header.e_phnum; i++) { // map the segments to memory
                    if (parser->prog_headers[i].p_type == PT_LOAD) {
                        map_segment_data_to_mem(i);
                    } else {
                        segment_data[i] = nullptr;
                    }
                }
                start_execution = reinterpret_cast<void(*)()>(parser->elf_header.e_entry); // turn the code segment start into a function ptr
                start_execution(); // execute executable code
                break;
            default:
                syscall_exit(0);
        }
    }
}
