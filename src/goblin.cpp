#include "../include/executable.hpp"

using namespace Goblin;

int main() {
    Executable* executable = new Executable("/bin/ls");

#ifdef DEBUG
    executable->full_print();
#endif
    executable->run();

    exit(0);
}
