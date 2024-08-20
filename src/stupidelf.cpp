#include "../include/runner.hpp"

#include <sys/mman.h>

using namespace Roee_ELF;

int main() {
    Runner* runner = new Runner("tests/hello-dl");
    runner->full_parse();
#ifdef DEBUG
    runner->full_print();
#endif
    runner->run();

    exit(0);
}
