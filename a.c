#include <elf.h>
#include <linux/auxvec.h>
#include <stdio.h>
#include <sys/auxv.h>
#include <unistd.h>

extern char **environ; // Environment variables
extern char **__auxv;  // Auxiliary vector

int main(int argc, char **argv, char **envp) {
    printf("first test: is envp and environ the same?\n");
    printf("envp: %p\n", envp);
    printf("environ: %p\n", environ);

    printf("second test: are they all part of argv?\n");
    printf("argv: %p\n", argv);
    printf("envp: %p\n", envp);
}
