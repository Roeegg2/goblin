#include "../include/parser.hpp"
#include "../include/utils.hpp"
#include "../include/syscalls.hpp"

#include <cstdint>
#include <elf.h>
#include <sys/mman.h>
#include <sys/fcntl.h>

#define MAP_SEGMENT_DATA(sect_data, sect_index) \
    mmap_wrapper(reinterpret_cast<void**>(&sect_data), NULL, sect_headers[sect_index].sh_size, PROT_READ, \
        MAP_PRIVATE, elf_file_fd, sect_headers[sect_index].sh_offset);

namespace Roee_ELF {
    Parser_64b::Parser_64b(const char* file_path) {
        init(file_path);
    }

    void Parser_64b::init(const char* file_path) {
        elf_file_path = file_path;
        elf_file_fd = syscall_open(file_path, O_RDONLY, 0);

        if (elf_file_fd < -1) {
            print_str_literal(STDOUT_FD, "Failed to open file\n");
            syscall_exit(1);
        }
    }

    void Parser_64b::full_parse(void) {
        parse_elf_header();
        parse_prog_headers();
        parse_sect_headers();
    }

#ifdef DEBUG
    void Parser_64b::full_print(void) const {
        print_file_info();
        print_prog_headers();
        print_sect_headers();
        // print_symtab();
    }

    void Parser_64b::print_file_info(void) const {
        print_str_literal(STDOUT_FD, "ISA: ");
        print_isa();
        print_str_literal(STDOUT_FD, "\nFile type: ");
        print_file_type();
        print_str_literal(STDOUT_FD, "\nEntry point: ");
        print_str_num(STDOUT_FD, elf_header.e_entry, 16);
        print_str_literal(STDOUT_FD, "\n");
    }

    void Parser_64b::print_isa(void) const {
        switch (elf_header.e_machine) {
            case 0x0:
                print_str_literal(STDOUT_FD, "No specific ISA");
                break;
            case 0x2:
                print_str_literal(STDOUT_FD, "SPARC");
                break;
            case 0x3:
                print_str_literal(STDOUT_FD, "x86");
                break;
            case 0x8:
                print_str_literal(STDOUT_FD, "MIPS");
                break;
            case 0x14:
                print_str_literal(STDOUT_FD, "PowerPC");
                break;
            case 0x16:
                print_str_literal(STDOUT_FD, "S390");
                break;
            case 0x28:
                print_str_literal(STDOUT_FD, "ARM");
                break;
            case 0x2A:
                print_str_literal(STDOUT_FD, "SuperH");
                break;
            case 0x32:
                print_str_literal(STDOUT_FD, "IA-64");
                break;
            case 0x3E:
                print_str_literal(STDOUT_FD, "x86-64");
                break;
            case 0xB7:
                print_str_literal(STDOUT_FD, "AArch64");
                break;
            case 0xF3:
                print_str_literal(STDOUT_FD, "RISC-V");
                break;
            default:
                print_str_literal(STDOUT_FD, "Other");
                break;
        }
    }

    void Parser_64b::print_file_type(void) const {
        switch (elf_header.e_type) {
            case 0x0:
                print_str_literal(STDOUT_FD, "NONE");
                break;
            case 0x1:
                print_str_literal(STDOUT_FD, "REL");
                break;
            case 0x2:
                print_str_literal(STDOUT_FD, "EXEC");
                break;
            case 0x3:
                print_str_literal(STDOUT_FD, "DYN");
                break;
            case 0x4:
                print_str_literal(STDOUT_FD, "CORE");
                break;
            default:
                print_str_literal(STDOUT_FD, "OTHER");
                break;
        }
    }

    void Parser_64b::print_ph_type(const uint16_t i) const {
        switch (prog_headers[i].p_type) {
            case PT_NULL:
                print_str_literal(STDOUT_FD, "NULL");
                break;
            case PT_LOAD:
                print_str_literal(STDOUT_FD, "LOAD");
                break;
            case PT_DYNAMIC:
                print_str_literal(STDOUT_FD, "DYNAMIC");
                break;
            case PT_INTERP:
                print_str_literal(STDOUT_FD, "INTERP");
                break;
            case PT_NOTE:
                print_str_literal(STDOUT_FD, "NOTE");
                break;
            case PT_SHLIB:
                print_str_literal(STDOUT_FD, "SHLIB");
                break;
            case PT_PHDR:
                print_str_literal(STDOUT_FD, "PHDR");
                break;
            case PT_TLS:
                print_str_literal(STDOUT_FD, "TLS");
                break;
            case PT_LOOS:
                print_str_literal(STDOUT_FD, "LOOS");
                break;
            case PT_HIOS:
                print_str_literal(STDOUT_FD, "HIOS");
                break;
            case PT_LOPROC:
                print_str_literal(STDOUT_FD, "LOPROC");
                break;
            case PT_HIPROC:
                print_str_literal(STDOUT_FD, "HIPROC");
                break;
            case PT_GNU_EH_FRAME:
                print_str_literal(STDOUT_FD, "GNUEH_FRAME");
                break;
            case PT_GNU_STACK:
                print_str_literal(STDOUT_FD, "GNU_STACK");
                break;
            case PT_GNU_RELRO:
                print_str_literal(STDOUT_FD, "GNU_RELRO");
                break;
            case PT_GNU_PROPERTY:
                print_str_literal(STDOUT_FD, "GNU_PROPERTY");
                break;
            default:
                print_str_literal(STDOUT_FD, "Unknown");
                break;
        }
    }

    void Parser_64b::print_prog_headers(void) const {
        print_str_literal(STDOUT_FD, "==== Program headers: ====");
        for (uint8_t i = 0; i < elf_header.e_phnum; i++) {
            print_str_literal(STDOUT_FD, "\n");

            print_str_literal(STDOUT_FD, "\nType: ");
            print_ph_type(i);

            print_str_literal(STDOUT_FD, "\nFlags: ");
            print_str_num(STDOUT_FD, prog_headers[i].p_flags, 2);

            print_str_literal(STDOUT_FD, "\nOffset: ");
            print_str_num(STDOUT_FD, prog_headers[i].p_offset, 16);

            print_str_literal(STDOUT_FD, "\nVirtual address: ");
            print_str_num(STDOUT_FD, prog_headers[i].p_vaddr, 16);

            print_str_literal(STDOUT_FD, "\nPhysical address: ");
            print_str_num(STDOUT_FD, prog_headers[i].p_paddr, 16);

            print_str_literal(STDOUT_FD, "\nFile size: ");
            print_str_num(STDOUT_FD, prog_headers[i].p_filesz, 16);

            print_str_literal(STDOUT_FD, "\nMemory size: ");
            print_str_num(STDOUT_FD, prog_headers[i].p_memsz, 16);

            print_str_literal(STDOUT_FD, "\nAlignment: ");
            print_str_num(STDOUT_FD, prog_headers[i].p_align, 16);

            print_str_literal(STDOUT_FD, "\n");
        }
        print_str_literal(STDOUT_FD, "\n");
    }

    void Parser_64b::print_sh_type(const uint16_t i) const {
        switch(sect_headers[i].sh_type) {
            case SHT_NULL:
                print_str_literal(STDOUT_FD, "NULL");
                break;
            case SHT_PROGBITS:
                print_str_literal(STDOUT_FD, "PROGBITS");
                break;
            case SHT_SYMTAB:
                print_str_literal(STDOUT_FD, "SYMTAB");
                break;
            case SHT_STRTAB:
                print_str_literal(STDOUT_FD, "STRTAB");
                break;
            case SHT_RELA:
                print_str_literal(STDOUT_FD, "RELA");
                break;
            case SHT_HASH:
                print_str_literal(STDOUT_FD, "HASH");
                break;
            case SHT_DYNAMIC:
                print_str_literal(STDOUT_FD, "DYNAMIC");
                break;
            case SHT_NOTE:
                print_str_literal(STDOUT_FD, "NOTE");
                break;
            case SHT_NOBITS:
                print_str_literal(STDOUT_FD, "NOBITS");
                break;
            case SHT_REL:
                print_str_literal(STDOUT_FD, "REL");
                break;
            case SHT_SHLIB:
                print_str_literal(STDOUT_FD, "SHLIB");
                break;
            case SHT_DYNSYM:
                print_str_literal(STDOUT_FD, "DYNSYM");
                break;
            case SHT_INIT_ARRAY:
                print_str_literal(STDOUT_FD, "INIT_ARRAY");
                break;
            case SHT_FINI_ARRAY:
                print_str_literal(STDOUT_FD, "FINI_ARRAY");
                break;
            case SHT_PREINIT_ARRAY:
                print_str_literal(STDOUT_FD, "PREINIT_ARRAY");
                break;
            case SHT_GROUP:
                print_str_literal(STDOUT_FD, "GROUP");
                break;
            case SHT_SYMTAB_SHNDX:
                print_str_literal(STDOUT_FD, "SYMTAB_SHNDX");
                break;
            case SHT_LOOS:
                print_str_literal(STDOUT_FD, "OS specific");
                break;
            case SHT_HIOS:
                print_str_literal(STDOUT_FD, "OS specific");
                break;
            case SHT_LOPROC:
                print_str_literal(STDOUT_FD, "Processor specific");
                break;
            case SHT_HIPROC:
                print_str_literal(STDOUT_FD, "Processor specific");
                break;
            case SHT_LOUSER:
                print_str_literal(STDOUT_FD, "User specific");
                break;
            case SHT_HIUSER:
                print_str_literal(STDOUT_FD, "User specific");
                break;
            default:
                print_str_literal(STDOUT_FD, "Other");
                break;
        }
    }

    void Parser_64b::print_sect_headers(void) const {
        print_str_literal(STDOUT_FD, "==== Section headers: ====");
        for (uint8_t i = 0; i < elf_header.e_shnum; i++) {
            print_str_literal(STDOUT_FD, "\n");

            print_str_literal(STDOUT_FD, "Name: ");
            // print_str(STDOUT_FD, sect_headers[i].name);

            print_str_literal(STDOUT_FD, "\nType: ");
            print_sh_type(i);

            print_str_literal(STDOUT_FD, "\nFlags: ");
            print_str_num(STDOUT_FD, sect_headers[i].sh_flags, 2);

            print_str_literal(STDOUT_FD, "\nAddress: ");
            print_str_num(STDOUT_FD, sect_headers[i].sh_addr, 16);

            print_str_literal(STDOUT_FD, "\nOffset: ");
            print_str_num(STDOUT_FD, sect_headers[i].sh_offset, 16);

            print_str_literal(STDOUT_FD, "\nSize: ");
            print_str_num(STDOUT_FD, sect_headers[i].sh_size, 16);

            print_str_literal(STDOUT_FD, "\nLink: ");
            print_str_num(STDOUT_FD, sect_headers[i].sh_link, 16);

            print_str_literal(STDOUT_FD, "\nInfo: ");
            print_str_num(STDOUT_FD, sect_headers[i].sh_info, 16);

            print_str_literal(STDOUT_FD, "\nAddress alignment: ");
            print_str_num(STDOUT_FD, sect_headers[i].sh_entsize, 16);

            print_str_literal(STDOUT_FD, "\nEntry size: ");
            print_str_num(STDOUT_FD, sect_headers[i].sh_entsize, 16);

            print_str_literal(STDOUT_FD, "\n");
        }
        print_str_literal(STDOUT_FD, "\n");
    }

    void Parser_64b::print_symtab() const {
        print_str_literal(STDOUT_FD, "==== Symbol table: ====");
        unsigned int ent_count = sect_headers[symtab_index].sh_size / sect_headers[symtab_index].sh_entsize;

        for (unsigned int i = 0; i < ent_count; i++) {
            print_str_literal(STDOUT_FD, "\n");

            print_str_literal(STDOUT_FD, "Name: ");
            // print_str(STDOUT_FD, symtab[i].name);

            print_str_literal(STDOUT_FD, "\nValue: ");
            print_str_num(STDOUT_FD, symtab_data[i].st_value, 16);

            print_str_literal(STDOUT_FD, "\nSize: ");
            print_str_num(STDOUT_FD, symtab_data[i].st_size, 16);

            print_str_literal(STDOUT_FD, "\nInfo: ");
            print_str_num(STDOUT_FD, symtab_data[i].st_info, 16);

            print_str_literal(STDOUT_FD, "\nOther: ");
            print_str_num(STDOUT_FD, symtab_data[i].st_other, 16);

            print_str_literal(STDOUT_FD, "\nSection index: ");
            print_str_num(STDOUT_FD, symtab_data[i].st_shndx, 16);

            print_str_literal(STDOUT_FD, "\n");
        }
    }
#endif

    inline void Parser_64b::check_elf_header_magic(void) { // sizeof(ELFMAG)
        read_elf_header_data(&elf_header.e_ident, SELFMAG, 0x0);
        if (memcmp(elf_header.e_ident, &ELFMAG, SELFMAG) != 0) {
            print_str_literal(STDOUT_FD, "Not an ELF file\n");
            syscall_exit(1);
        }
    }

    inline void Parser_64b::check_elf_header_class(void) {
        read_elf_header_data(&elf_header.e_ident[EI_CLASS], sizeof(elf_header.e_ident[EI_CLASS]));
        if (elf_header.e_ident[EI_CLASS] != ELFCLASS64) {
            print_str_literal(STDOUT_FD, "ELF file isn't 64 bit. This loader only supports 64 bit.\n");
            syscall_exit(1);
        }
    }

    void Parser_64b::read_elf_header_data(void* data, const uint8_t bytes, const int32_t offset) {
        if (offset > 0) {
            syscall_lseek(elf_file_fd, offset, 0);
        }
        syscall_read(elf_file_fd, reinterpret_cast<char*>(data), bytes);
    }

    /* Get the ELF file entry point from the ELF header */
    void Parser_64b::parse_elf_header(void) {
        check_elf_header_magic();
        check_elf_header_class();

        read_elf_header_data(&elf_header.e_ident[EI_DATA], sizeof(elf_header.e_ident[EI_DATA]), 0x5);
        read_elf_header_data(&elf_header.e_type, sizeof(elf_header.e_type), 0x10);
        read_elf_header_data(&elf_header.e_machine, sizeof(elf_header.e_machine), 0x12);
        read_elf_header_data(&elf_header.e_entry, sizeof(elf_header.e_entry), 0x18);
        read_elf_header_data(&elf_header.e_phoff, sizeof(elf_header.e_phoff), 0x20);
        read_elf_header_data(&elf_header.e_shoff, sizeof(elf_header.e_shoff), 0x28);
        read_elf_header_data(&elf_header.e_phentsize, sizeof(elf_header.e_phentsize), 0x36);
        read_elf_header_data(&elf_header.e_phnum, sizeof(elf_header.e_phnum), 0x38);
        read_elf_header_data(&elf_header.e_shentsize, sizeof(elf_header.e_shentsize), 0x3a);
        read_elf_header_data(&elf_header.e_shnum, sizeof(elf_header.e_shnum), 0x3c);
        read_elf_header_data(&elf_header.e_shstrndx, sizeof(elf_header.e_shstrndx), 0x3e);
    }

    /* Get the program header data */
    void Parser_64b::parse_prog_headers(void) {
        mmap_wrapper(reinterpret_cast<void**>(&prog_headers), NULL, elf_header.e_phnum * sizeof(Elf64_Phdr),
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        for (uint16_t i = 0; i < elf_header.e_phnum; i++) {
            syscall_lseek(elf_file_fd, elf_header.e_phoff + i * (elf_header.e_phentsize), 0);

            syscall_read(elf_file_fd, reinterpret_cast<char*>(&prog_headers[i].p_type), 4); // segment type
            syscall_read(elf_file_fd, reinterpret_cast<char*>(&prog_headers[i].p_flags), 4); // segment flags
            syscall_read(elf_file_fd, reinterpret_cast<char*>(&prog_headers[i].p_offset), 8); // offset in file
            syscall_read(elf_file_fd, reinterpret_cast<char*>(&prog_headers[i].p_vaddr), 8); // virtual address in memory
            syscall_read(elf_file_fd, reinterpret_cast<char*>(&prog_headers[i].p_paddr), 8); // physical address in memory
            syscall_read(elf_file_fd, reinterpret_cast<char*>(&prog_headers[i].p_filesz), 8); // size of segment in file
            syscall_read(elf_file_fd, reinterpret_cast<char*>(&prog_headers[i].p_memsz), 8); // size of segment in memory
            syscall_read(elf_file_fd, reinterpret_cast<char*>(&prog_headers[i].p_align), 8); // alignment
        }
    }

    void Parser_64b::parse_sect_headers(void) {
        mmap_wrapper(reinterpret_cast<void**>(&sect_headers), NULL, elf_header.e_shnum * sizeof(Elf64_Shdr),
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        MAP_SEGMENT_DATA(shstrtab_data, elf_header.e_shstrndx); // getting the .shstrtab section data
        for (uint16_t i = 0; i < elf_header.e_shnum; i++) {
            // syscall_lseek(elf_file_fd, elf.offset + i * sh_data.entry_size, 0);
            syscall_lseek(elf_file_fd, elf_header.e_shoff + (i * elf_header.e_shentsize), 0);

            syscall_read(elf_file_fd, reinterpret_cast<char*>(&sect_headers[i].sh_name), 4); // offset into the .shstrtab section
            syscall_read(elf_file_fd, reinterpret_cast<char*>(&sect_headers[i].sh_type), 4); // type of section
            syscall_read(elf_file_fd, reinterpret_cast<char*>(&sect_headers[i].sh_flags), 8); // section attributes
            syscall_read(elf_file_fd, reinterpret_cast<char*>(&sect_headers[i].sh_addr), 8); // virtual address in memory
            syscall_read(elf_file_fd, reinterpret_cast<char*>(&sect_headers[i].sh_offset), 8); // offset in file
            syscall_read(elf_file_fd, reinterpret_cast<char*>(&sect_headers[i].sh_size), 8); // size of section
            syscall_read(elf_file_fd, reinterpret_cast<char*>(&sect_headers[i].sh_link), 4); // index of a related section
            syscall_read(elf_file_fd, reinterpret_cast<char*>(&sect_headers[i].sh_info), 4); // depends on section type
            syscall_read(elf_file_fd, reinterpret_cast<char*>(&sect_headers[i].sh_addralign), 8); // alignment
            syscall_read(elf_file_fd, reinterpret_cast<char*>(&sect_headers[i].sh_entsize), 8); // size of each entry if section holds a table

            get_section_data(i);
        }
    }

    void Parser_64b::get_section_data(const uint16_t i) {
        switch (sect_headers[i].sh_type) {
            case SHT_SYMTAB:
                symtab_index = i;
                MAP_SEGMENT_DATA(symtab_data, symtab_index)
                break;
            // case SHT_STRTAB:
            //     if (i != elf_header.e_shstrndx) {
            //         strtab_index = i;
            //         MAP_SEGMENT_DATA(strtab_data, i)
            //     }
        }
    }

    // void Parser_64b::get_section_data(const uint16_t i) {
    //     static int64_t strtab_offset = get_string_offset(".")
    //     switch()
    //     if (sect_headers[i].size == 0) { // section has no data to read
    //         return;
    //     }

    //     sect_headers[i].data = reinterpret_cast<void*>(syscall_mmap(sect_headers[i].addr, sect_headers[i].size,
    //             PROT_WRITE, MAP_PRIVATE, elf_file_fd, sect_headers[i].offset));

    //     if (sect_headers[i].data == MAP_FAILED) {
    //         syscall_write(2, "mmap failed\n", 12);
    //         syscall_exit(1);
    //     }

    //     if (syscall_mprotect(reinterpret_cast<uint64_t>(sect_headers[i].data), sect_headers[i].size,
    //             elf_perm_to_mmap_perms(sect_headers[i].flags)) == -1) { // after write, change to the correct permissions
    //         syscall_write(2, "mprotect failed\n", 16);
    //         syscall_exit(1);
    //     }
    // }
};
