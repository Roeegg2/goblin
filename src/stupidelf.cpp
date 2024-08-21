#include "../include/runner.hpp"

#include <sys/mman.h>

using namespace Roee_ELF;

int main() {
    Runner* runner = new Runner("tests/hello-dl");
#ifdef DEBUG
    runner->full_print();
#endif
    runner->run();

    exit(0);
}
