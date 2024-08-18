#include "../include/runner.hpp"
#include "../include/syscalls.hpp"
#include "../include/utils.hpp"

#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/fcntl.h>

namespace Roee_ELF {
    constexpr Elf64_Addr loader_base_addr = 0x500000;
    void Runner::get_taken_mem_ranges(void) {

    }

    void Runner::remap_loader_segments(void) {
        void *ptr0, *ptr1, *ptr2;
        ptr0 = ptr1 = ptr2 = 0x0;
        // reserve the new mem
        // mmap_wrapper(&ptr0, loader_base_addr + 0x0, 0x1000, PROT_READ, MAP_PRIVATE, -1, 0);
        // mmap_wrapper(&ptr1, loader_base_addr + 0x1000, 0x3000, PROT_READ | PROT_EXEC, MAP_PRIVATE, -1, 0);
        // mmap_wrapper(&ptr2, loader_base_addr + 0x4000, 0x1000, PROT_READ, MAP_PRIVATE, -1, 0);
        mmap_wrapper(&ptr0, 0x0, 0x1000, PROT_READ, MAP_PRIVATE, -1, 0);
        mmap_wrapper(&ptr1, 0x0, 0x3000, PROT_READ | PROT_EXEC, MAP_PRIVATE, -1, 0);
        mmap_wrapper(&ptr2, 0x0, 0x1000, PROT_READ, MAP_PRIVATE, -1, 0);

        // copy to the new mem
        memcpy(ptr0, reinterpret_cast<void*>(0x400000 + 0x0), 0x1000);
        memcpy(ptr1, reinterpret_cast<void*>(0x400000 + 0x1000), 0x3000);
        memcpy(ptr2, reinterpret_cast<void*>(0x400000 + 0x4000), 0x1000);
        // remove old mapping
        syscall_munmap(0x400000 + 0x0, 0x1000);
        syscall_munmap(0x400000 + 0x1000, 0x3000);
        syscall_munmap(0x400000 + 0x4000, 0x1000);
    }

    void Runner::map_pt_load_segment(const uint8_t i) {
        mmap_wrapper(&segment_data[i], prog_headers[i].p_vaddr, prog_headers[i].p_memsz,
            PROT_READ | PROT_WRITE, MAP_PRIVATE, elf_file_fd, PAGE_ALIGN_DOWN(prog_headers[i].p_offset));

        // if segments arent page aligned, we need to adjust the pointer after the mapping
        segment_data[i] = reinterpret_cast<void*>(prog_headers[i].p_vaddr);

        // as specified by the format, we need to zero out the memory that is not in the file
        memset(reinterpret_cast<void*>(reinterpret_cast<uint8_t*>(segment_data[i]) + prog_headers[i].p_filesz),
            0x0, prog_headers[i].p_memsz - prog_headers[i].p_filesz);

        // change the permissions of the segment to what they should be
        if (syscall_mprotect(reinterpret_cast<uint64_t>(segment_data[i]), prog_headers[i].p_memsz,
            elf_perm_to_mmap_perms(prog_headers[i].p_flags)) == -1) {
            print_str_literal(STDOUT_FD, "mmprotect failed\n");
            syscall_exit(1);
        }
    }

    void Runner::map_segments(void) {
        segment_data = reinterpret_cast<void**>(syscall_mmap(0x0, sizeof(void*) * elf_header.e_phnum,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));

        for (int8_t i = 0; i < elf_header.e_phnum; i++) { // map the segments to memory
            switch (prog_headers[i].p_type) {
                case PT_LOAD:
                    map_pt_load_segment(i);
                    break;
                case PT_DYNAMIC:
                    dynamic_segment_index = i;
                    mmap_wrapper(&segment_data[i], 0x0, prog_headers[i].p_memsz, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE, elf_file_fd, PAGE_ALIGN_DOWN(prog_headers[i].p_offset));
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
                remap_loader_segments();
                map_segments();
                start_execution = reinterpret_cast<void(*)()>(elf_header.e_entry); // turn the code segment start into a function ptr
                start_execution(); // execute executable code
                break;
            default:
                syscall_exit(0);
        }
    }
}
