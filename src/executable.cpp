#include "../include/executable.hpp"

#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <elf.h>
#include <sys/mman.h>

namespace Roee_ELF {
    Executable::Executable(const char* file_path)
        : Loadable(file_path) { }

    Executable::~Executable(void) { }

    void Executable::run(void) { // elf_header.e_entry 0x401655
        if (elf_header.e_type == ET_EXEC) {
            remap_loader_segments();
        }
        build_shared_objs_tree();

#ifdef DEBUG
        if (dyn_seg_index > 0) {
            print_dynamic_segment();
            std::cout << "Starting execution...\n";
        }
#endif
        void (*start_execution)(void) = reinterpret_cast<void(*)()>(elf_header.e_entry + load_base_addr);
        start_execution();
    }

    uint8_t Executable::proc_maps_perms_to_mmap_perms(const char str_perms[4]) {
        uint8_t ret_perms = 0;
        if (str_perms[0] == 'r') {
            ret_perms |= PROT_READ;
        } else if (str_perms[0] == 'w') {
            ret_perms |= PROT_WRITE;
        } else if (str_perms[0] == 'x') {
            ret_perms |= PROT_EXEC;
        }

        return ret_perms;
    }

    void Executable::remap_loader_segments(void) {
        std::vector<struct loader_segment> s;
        std::ifstream proc_maps("/proc/self/maps");
        if (!proc_maps.is_open()) {
            std::cerr << "Failed to open /proc/self/maps\n";
            exit(1);
        }

        std::string line;
        while (std::getline(proc_maps, line)) {
            if (line.find("stupidelf") != std::string::npos) {
                std::string start_addr_str = line.substr(0, line.find('-'));
                std::string end_addr_str = line.substr(line.find('-') + 1, line.find(' '));
                std::string perms = line.substr(line.find(' ') + 1, line.find(' '));

                const Elf64_Addr start_addr = std::stoull(start_addr_str, nullptr, 16);
                const Elf64_Addr end_addr = std::stoull(end_addr_str, nullptr, 16);
                const uint8_t mmap_perms = proc_maps_perms_to_mmap_perms(perms.c_str());
                s.push_back({start_addr, end_addr, mmap_perms});
            }
        }

        void* new_base = mmap(NULL, s.end()->org_end_addr - s[0].org_start_addr,
            PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        std::memcpy(new_base, reinterpret_cast<void*>(s[0].org_start_addr), s.end()->org_end_addr - s[0].org_start_addr);

        // asm volatile (
        //     "mov %[addr], %%rax\n"  // Move the target address into the RAX register
        //     "jmp *%%rax\n"          // Jump to the address stored in RAX
        //     :                       // No output operands
        //     : [addr] "r"(reinterpret_cast<Elf64_Addr>(new_base) + ) // Input operand
        //     : "rax"                 // Clobbers RAX
        // );
    }
}
