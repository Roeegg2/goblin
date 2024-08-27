#include "../include/executable.hpp"

using namespace Roee_ELF;

int main() {
    Executable* executable = new Executable("tests/ifunc-nolibc");

#ifdef DEBUG
    executable->full_print();
#endif
    executable->run();

    exit(0);
}
