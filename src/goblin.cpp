#include "../include/executable.hpp"

#include <cstdint>
#include <cstring>
#include <iostream>
#include <unistd.h>

using namespace Goblin;

#define _GOBLIN_USUAGE " Usage: ./goblin <executable> [-b=<eager|lazy>][-sr=<elf-hash|gnu-hash|symtab|optimal>]"
static char *parse_options(const int argc, char **argv, options_t &options) {
    auto parse_binding = [&](const char *binding) {
        if (std::strcmp(binding, "eager") == 0) {
            options.binding = BINDING_EAGER;
        } else if (std::strcmp(binding, "lazy") == 0) {
            options.binding = BINDING_LAZY;
        } else {

            _GOBLIN_PRINT_ERR("Invalid binding option: " << binding << _GOBLIN_USUAGE);
        }
    };

    auto parse_symbol_resolution = [&](const char *symbol_resolution) {
        if (std::strcmp(symbol_resolution, "elf-hash") == 0) {
            options.symbol_resolution = SYMBOL_RESOLUTION_ELF_HASH;
        } else if (std::strcmp(symbol_resolution, "gnu-hash") == 0) {
            options.symbol_resolution = SYMBOL_RESOLUTION_GNU_HASH;
        } else if (std::strcmp(symbol_resolution, "symtab") == 0) {
            options.symbol_resolution = SYMBOL_RESOLUTION_SYMTAB;
        } else {
            _GOBLIN_PRINT_ERR("Invalid symbol resolution option: " << symbol_resolution << _GOBLIN_USUAGE);
        }
    };

    if (access(argv[1], F_OK) == -1) {
        _GOBLIN_PRINT_ERR("File not found: " << argv[1] << _GOBLIN_USUAGE);
    }

    { // there isn't need for RAII block here, but im leaving it here in case i need to add more stuff at the end
        int i = 2;
        for (; i < argc; i++) {
            if (std::strstr(argv[i], "-b=") == argv[i]) {
                parse_binding(argv[i] + 3);
            } else if (std::strstr(argv[i], "-sr=") == argv[i]) {
                parse_symbol_resolution(argv[i] + 4);
            } else {
                _GOBLIN_PRINT_ERR("Invalid option: " << argv[i] << _GOBLIN_USUAGE);
            }
        }
        return argv[i];
    }
}
#undef _GOBLIN_USUAGE

int main(int argc, char **argv) {
    options_t options = {
        .binding = BINDING_EAGER,
        .symbol_resolution = SYMBOL_RESOLUTION_ELF_HASH,
    };
    *argv = parse_options(argc, argv, options); // move argv to the params passed to the actual executable, not Goblin
    Executable *executable = new Executable(argv[1], options);

#ifdef DEBUG
    executable->full_print();
#endif
    executable->run(argc, argv);

    return 0;
}
