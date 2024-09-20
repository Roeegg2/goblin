#include "../include/executable.hpp"

#include <cstring>
#include <iostream>

using namespace Goblin;

static void parse_options(int argc, char **argv, options_t &options) {
    auto error_out = []() {
        std::cerr << "Usage: ./goblin <executable> [-b=<eager|lazy>][-sr=<elf-hash|gnu-hash|symtab|optimal>]"
                  << "\n";
        exit(1);
    };

    auto parse_binding = [&](const char *binding) {
        if (std::strcmp(binding, "eager") == 0) {
            options.binding = BINDING_EAGER;
        } else if (std::strcmp(binding, "lazy") == 0) {
            options.binding = BINDING_LAZY;
        } else {
            std::cerr << "Invalid binding option: " << binding << "\n";
            error_out();
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
            std::cerr << "Invalid symbol resolution option: " << symbol_resolution << "\n";
            error_out();
        }
    };

    if (access(argv[1], F_OK) == -1) {
        std::cerr << "File not found\n";
        error_out();
    }

    for (int i = 2; i < argc; i++) {
        if (std::strstr(argv[i], "-b=") == argv[i]) {
            parse_binding(argv[i] + 3);
        } else if (std::strstr(argv[i], "-sr=") == argv[i]) {
            parse_symbol_resolution(argv[i] + 4);
        } else {
            std::cerr << "Invalid option: " << argv[i] << "\n";
            error_out();
        }
    }
}

int main(int argc, char **argv) {
    /*int main(void) {*/
    options_t options = {
        .binding = BINDING_EAGER,
        .symbol_resolution = SYMBOL_RESOLUTION_OPTIMAL,
    };
    parse_options(argc, argv, options);
    Executable *executable = new Executable(argv[1], options);

#ifdef DEBUG
    executable->full_print();
#endif
    executable->run();

    return 0;
}
