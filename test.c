#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>

const char* buff = "\xbf\x01\x00\x00\x00\x48\xbe\x00\x20\x40\x00\x00\x00\x00\x00\xba\x0d\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x48\x31\xff\xb8\x3c\x00\x00\x00\x0f\x05\x00";
const int buff_len = 39;

int main() {
    printf("main addr is %p\n", main);
    printf("buff addr is %p\n", buff);

    void* foo = (void*)buff;
    foo = (void*)((unsigned long)foo & (~0xfff));
    int ret = mprotect((void*)(foo), buff_len, PROT_EXEC | PROT_READ);
    if (ret == -1) {
        printf("mprotect failed: error %d\n", errno);
        return -1;
    }

    printf("before jump\n");
    void (*f)(void) = (void*)buff;
    f();
    printf("after jump\n");
    return 0;
}