#ifndef RUNNER_HPP
#define RUNNER_HPP

#include "parser.hpp"
#include <elf.h>

namespace Roee_ELF {
    class Runner final : public Parser_64b {
    public:
        Runner(const char* file_path);
        void run(void);
#ifdef DEBUG
        void print_dynamic_segment(void) const;
        void print_dynamic_tag(Elf64_Sxword tag) const;
#endif
    private:
        void handle_relocations(void);
        void apply_dyn_relocations(Elf64_Off rela_table);
        void map_load_segments(void);
        void map_dyn_segment(void);
        void set_correct_permissions(void);

        uint8_t get_page_count(Elf64_Xword memsz, Elf64_Addr addr);

    private:
        void (*start_execution)(void);
        void** segment_data;
        int elf_file_fd;
        Elf64_Addr load_base_addr;
    };
}

#endif
