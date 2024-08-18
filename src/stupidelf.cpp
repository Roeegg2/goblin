#include "../include/parser.hpp"
#include "../include/runner.hpp"
#include "../include/syscalls.hpp"
#include "../include/utils.hpp"

#include <sys/mman.h>

using namespace Roee_ELF;

int main() {
    Runner* runner;
    mmap_wrapper(reinterpret_cast<void**>(&runner), 0x0, sizeof(Parser_64b), PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    runner->init("tests/hello");
    runner->full_parse();
#ifdef DEBUG
    runner->full_print();
#endif
    runner->run();

    syscall_exit(0);
}
