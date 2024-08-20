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
        void print_dynamic_segment(void);
        void print_dynamic_tag(Elf64_Sxword tag);
#endif
    private:
        void map_pt_load_segment(const uint8_t i);
        void map_segments(void);
        void get_taken_mem_ranges(void);
        void parse_dynamic_segment(void);

    private:
        void (*start_execution)(void);
        void** segment_data;
        int16_t dyn_seg_index;
        int elf_file_fd;
    };
}

#endif
