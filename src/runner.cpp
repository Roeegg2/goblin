#include "../include/runner.hpp"
#include "../include/syscalls.hpp"
#include "../include/utils.hpp"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/fcntl.h>

namespace Roee_ELF {
    void Runner::get_taken_mem_ranges(void) {

    }

    void Runner::remap_loader_segments(void) {

    }

    void Runner::map_pt_load_segment(const uint8_t i) {
        mmap_wrapper(&segment_data[i], prog_headers[i].p_vaddr, prog_headers[i].p_memsz,
            PROT_READ | PROT_WRITE, MAP_PRIVATE, elf_file_fd, prog_headers[i].p_offset);

        // if segments arent page aligned, we need to adjust the pointer after the mapping
        segment_data[i] = reinterpret_cast<void*>(prog_headers[i].p_vaddr);

        // as specified by the format, we need to zero out the memory that is not in the file
        memset(reinterpret_cast<void*>(reinterpret_cast<uint8_t*>(segment_data[i]) + prog_headers[i].p_filesz),
            NULL, prog_headers[i].p_memsz - prog_headers[i].p_filesz);

        // change the permissions of the segment to what they should be
        if (syscall_mprotect(reinterpret_cast<uint64_t>(segment_data[i]), prog_headers[i].p_memsz,
            elf_perm_to_mmap_perms(prog_headers[i].p_flags)) == -1) {
            print_str_literal(STDOUT_FD, "mmprotect failed\n");
            syscall_exit(1);
        }
    }

    void Runner::map_segments(void) {
        segment_data = reinterpret_cast<void**>(syscall_mmap(NULL, sizeof(void*) * elf_header.e_phnum,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));

        for (int8_t i = 0; i < elf_header.e_phnum; i++) { // map the segments to memory
            switch (prog_headers[i].p_type) {
                case PT_LOAD:
                    map_pt_load_segment(i);
                    break;
                case PT_DYNAMIC:
                    dynamic_segment_index = i;
                    mmap_wrapper(&segment_data[i], NULL, prog_headers[i].p_memsz, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE, elf_file_fd, prog_headers[i].p_offset);
                    break;
                default:
                    segment_data[i] = nullptr;
            }
        }
    }

    void Runner::run(void) { //elf_header.e_entry 0x401655
        switch (syscall_fork()) {
            case -1:
                print_str_literal(STDOUT_FD, "fork failed\n");
                syscall_exit(1);
                break;
            case 0:
#ifdef DEBUG
                print_str_literal(STDOUT_FD, "Starting execution...\n");
#endif
                map_segments();
                start_execution = reinterpret_cast<void(*)()>(elf_header.e_entry); // turn the code segment start into a function ptr
                start_execution(); // execute executable code
                break;
            default:
                syscall_exit(0);
        }
    }
}
