#include <cstdlib>
#include <cstring>
#include <iostream>

#include "parser.hpp"
#include "runner.hpp"

using namespace Roee_ELF;

int main(int argc, char** argv) {
    std::ifstream file("test_progs/hello", std::ios::in | std::ios::binary);

    Parser_64b* const parser = new Parser_64b(file);
    Runner* const runner = new Runner(parser);

    parser->parse_elf_header();
    parser->parse_prog_headers();

    runner->run();

    return 0;
}

/*
finish ELF pdf
skim over elf series
descriptor tables
*/