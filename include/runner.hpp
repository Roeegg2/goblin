#ifndef RUNNER_HPP
#define RUNNER_HPP

#include "parser.hpp"

namespace Roee_ELF {
    struct mem_range {
        uint64_t start;
        uint64_t end;
    };

    class Runner final {
    public:
        Runner(Parser_64b* const parser);
        void init(Parser_64b* const parser);
        void run(void);

    private:
        void remap_loader_segments(void);
        void map_segment_data_to_mem(const uint8_t i);
        void map_segments(void);
        void get_taken_mem_ranges(void);

    private:
        Parser_64b* parser;
        void (*start_execution)(void);
        void** segment_data;
        struct mem_range* segment_mem_ranges;
    };
}

#endif
