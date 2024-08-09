#include "../include/parser.hpp"
#include "../include/runner.hpp"
#include "../include/syscalls.hpp"
#include "../include/utils.hpp"

#include <sys/mman.h>

using namespace Roee_ELF;

int main() {
    Parser_64b* parser = reinterpret_cast<Parser_64b*>(syscall_mmap(NULL, sizeof(Parser_64b), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    Runner* runner = reinterpret_cast<Runner*>(syscall_mmap(NULL, sizeof(Runner), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));

    parser->init("tests/chello");
    runner->init(parser);

    parser->full_parse();
#ifdef DEBUG
    parser->full_print();
#endif
    runner->run();

    syscall_exit(0);
}
