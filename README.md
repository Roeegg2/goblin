# Goblin

GOBLIN - the Generally Ok Binary Linker and INterpreter

Goblin is a work-in-progress ELF binary linker and interpreter, written out of curiosity to see how far one could get about loading and
dynamically linking ELF binaries in userspace.
My aim with this project is to replace `ld-linux` (and a bit of the Linux loader) as much as possible in userspace.

Currently only supports x86_64 binaries.

Features:
- [x] full shared object path resolution (RPATH, RUNPATH, LD_LIBRARY_PATH, etc.) (except for /etc/ld.so.cache)
- [x] eager binding
- [ ] lazy binding
- [x] ELF hash
- [ ] GNU hash
- [x] statically linked executables
- [x] dynamically linked executables
- [x] statically linked glibc executables
- [ ] dynamically linked glibc executables
- [ ] static TLS support
- [ ] dynamic TLS support
- [ ] dlopen() support
