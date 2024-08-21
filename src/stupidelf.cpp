#include "../include/runner.hpp"

#include <sys/mman.h>

using namespace Roee_ELF;

int main() {
    Runner* loader = new Runner("tests/hello");

#ifdef DEBUG
    loader->full_print();
#endif
    loader->run();

    exit(0);
}
