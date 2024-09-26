#include <linux/auxvec.h>
#include <stdio.h>
#include <sys/auxv.h>
#include <unistd.h>

extern char **environ; // This is typically declared in <unistd.h>

int main(int argc, char *argv[], char *envp[]) {
    unsigned long *auxv;

    // We can find the address of the auxiliary vector in envp
    for (char **env = envp; *env != 0; env++) {
        if (*env == NULL)
            break; // Safeguard against NULL
    }

    // Cast envp to unsigned long pointer to traverse
    auxv = (unsigned long *)envp;

    // Iterate through the auxiliary vector
    while (*auxv != 0) {
        unsigned long type = *auxv++;
        unsigned long value = *auxv++;

        switch (type) {
        case AT_PHDR:
            printf("AT_PHDR: %lx\n", value);
            break;
        case AT_PAGESZ:
            printf("AT_PAGESZ: %lx\n", value);
            break;
        // Handle other auxiliary vector entries as needed
        default:
            break;
        }
    }

    return 0;
}
