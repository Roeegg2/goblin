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
        Parser_64b* parser;
    };
}

#endif