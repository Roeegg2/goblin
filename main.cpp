#include <cstdlib>
#include <cstring>
#include <iostream>

#include "parser.hpp"
#include "runner.hpp"

using namespace Roee_ELF;

int main(int argc, char** argv) {
    Parser_64b* const parsed_info = new Parser_64b("test_progs/test3_stdlib");
    Runner* const runner = new Runner(parsed_info);

    parsed_info->parse_elf_header();
    parsed_info->parse_prog_headers();
#ifdef DEBUG
    parsed_info->print_file_info();
#endif

    runner->run();

    return 0;
}

/*
finish ELF pdf
skim over elf series
descriptor tables
*/