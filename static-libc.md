# Initilization of glibc static executables

## Disclaimer

I will be analyzing x86_64, don't know which glibc version (latest as of publishing this). Things _should_ be faily similar for other architectures and versions though. If anyway you're reading this in the future, just be aware of that

anyway lets get started

## Analysis

As usually, code starts at `_start`. 
It does some things, mainly setting up the stack and calling `__libc_start_main` with the arguments passed to the program. (auxiliary vector, argc, argv, envp, inits + finis, etc). Code is at start.S in glibc source code, under `sysdeps/x86_64/start.S` iirc.

It then calls `__libc_start_main`. Let's analyze it:

`_start():` 
    `__libc_start_main():`
        - gets environment variables from stack
        - stores the the stack_end
        - finds the auxillary vector
        - calls `_dl_aux_init()`:
            - calls `_dl_parse_auxv():` to set up the parsed auxv values
                no much to elaborate here, just parsing the values from the auxv vector so it'll be easier to access them later
            - initlisizes rest of values from auxv (_dl_phdr, _dl_phnum, etc)
        - calls `tunables_init()`:
            - sets up the tunables (see comment at the end for more info)
        - calls ARCH_INIT_CPU_FEATURES() - 





### tunables

this is a relatively new feature in glibc (as of today, that is) which allows the user to modify some of glibc's behaviour. (For example: ELF hwcap, stack size, and many more. its really worth checking it out, it has some neat options I didn't know about)
as I understood, it was made to have a unified way to modify glibc's behaviour at runtime, since up until now you had to use various differnt environment variables to do that, which was a bit messy.
