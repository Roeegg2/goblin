#include "../include/executable.hpp"

#include <cstdint>
#include <cstring>
#include <iostream>
#include <unistd.h>

using namespace Goblin;

#define _GOBLIN_USUAGE " Usage: ./goblin <executable> [-b=<eager|lazy>][-sr=<elf-hash|gnu-hash|symtab|optimal>]"
static uint16_t parse_options(const int argc, char **argv, __attribute__((unused)) options_t &options) {
    // TODO: add support for options
    if (argc < 2) {
        _GOBLIN_PRINT_ERR("No executable provided" << _GOBLIN_USUAGE);
    }

    if ((access(argv[1], F_OK) == -1)) {
        _GOBLIN_PRINT_ERR("File not found: " << argv[1] << _GOBLIN_USUAGE);
    }

    return 1;
}
#undef _GOBLIN_USUAGE

int main(int argc, char **argv) {
    options_t options = {
        .binding = BINDING_EAGER,
        .symbol_resolution = SYMBOL_RESOLUTION_ELF_HASH,
    };
    int i = parse_options(argc, argv, options); // move argv to the params passed to the actual executable, not Goblin
    Executable *executable = new Executable(argv[1], options);

#ifdef DEBUG
    executable->full_print();
#endif
    executable->run(argc - i, argv + i);

    return 0;
}
