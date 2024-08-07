#ifndef RUNNER_HPP
#define RUNNER_HPP

#include "parser.hpp"

namespace Roee_ELF {
    class Runner final {
    public:
        Runner(Parser_64b* const parser);
        void init(Parser_64b* const parser);
        void run(void);

    private:
        void map_segment_data_to_mem(const u8 i);

        private:
        Parser_64b* parser;
        void (*start_execution)(void);
    };
}

#endif
