#include "parser.hpp"

using namespace Roee_ELF;

int main() {
    std::ifstream file("../hello", std::ios::in | std::ios::binary);
    Parser_64b* const parser = new Parser_64b(file);

    parser->parse_isa();
    parser->parse_file_type();
    parser->parse_entry_point();
    parser->parse_prog_headers();

    return 0;
}