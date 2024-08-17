#ifndef RUNNER_HPP
#define RUNNER_HPP

#include "parser.hpp"

namespace Roee_ELF {
    struct mem_range {
        uint64_t start;
        uint64_t end;
    };

    class Runner final : public Parser_64b {
    public:
        void run(void);

    private:
        void remap_loader_segments(void);
        void map_pt_load_segment(const uint8_t i);
        void map_segments(void);
        void get_taken_mem_ranges(void);

    private:
        void (*start_execution)(void);
        void** segment_data;
        struct mem_range* segment_mem_ranges;
        uint8_t dynamic_segment_index;
    };
}

#endif
