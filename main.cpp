#include "parser.hpp"
#include "runner.hpp"

using namespace Roee_ELF;

int main() {
    std::ifstream file("test_progs/test", std::ios::in | std::ios::binary);

    Parser_64b* const parser = new Parser_64b(file);
    Runner* const runner = new Runner(parser);

    parser->parse_isa();
    parser->parse_file_type();
    parser->parse_entry_point();
    parser->parse_prog_headers();

    runner->run();

    return 0;
}