#include "../include/parser.hpp"
#include "../include/utils.hpp"
#include "../include/syscalls.hpp"

#include <sys/mman.h>

namespace Roee_ELF {

    Parser_64b::Parser_64b(const char* file_name) {
        init(file_name);
    }

    void Parser_64b::init(const char* file_name) {
        fd = syscall_open(file_name, 0x2, 0);

        if (fd < -1) {
            print_str_literal(STDERR_FD, "Failed to open file\n");
            syscall_exit(1);
        }
    }

#ifdef DEBUG
    void Parser_64b::print_file_info(void) const {
        print_str_literal(STDOUT_FD, "ISA: ");
        print_isa();
        print_str_literal(STDOUT_FD, "\nFile type: ");
        print_file_type();
        print_str_literal(STDOUT_FD, "\nEntry point: ");
        print_str_num(STDOUT_FD, elf_header.entry_point, 16);
        print_str_literal(STDOUT_FD, "\n");
    }

    void Parser_64b::print_isa(void) const {
        switch (elf_header.isa) {
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
        switch (elf_header.file_type) {
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

    void Parser_64b::print_ph_type(const u16 i) const {
        switch (prog_headers[i].type) {
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
            case PT_GNUEH_FRAME:
                print_str_literal(STDOUT_FD, "GNUEH_FRAME");
                break;
            case PT_GNUSTACK:
                print_str_literal(STDOUT_FD, "GNU_STACK");
                break;
            case PT_GNU_RELRO:
                print_str_literal(STDOUT_FD, "GNU_RELRO");
                break;
            case PT_GNUPROPERTY:
                print_str_literal(STDOUT_FD, "GNU_PROPERTY");
                break;
            default:
                print_str_literal(STDOUT_FD, "Unknown");
                break;
        }
    }

    void Parser_64b::print_prog_headers(void) const {
        print_str_literal(STDOUT_FD, "==== Program headers: ====");
        for (u8 i = 0; i < ph_data.entry_count; i++) {
            print_str_literal(STDOUT_FD, "\n");

            print_str_literal(STDOUT_FD, "\nType: ");
            print_ph_type(i);

            print_str_literal(STDOUT_FD, "\nOffset: ");
            print_str_num(STDOUT_FD, prog_headers[i].offset, 16);

            print_str_literal(STDOUT_FD, "\nVirtual address: ");
            print_str_num(STDOUT_FD, prog_headers[i].v_addr, 16);

            print_str_literal(STDOUT_FD, "\nPhysical address: ");
            print_str_num(STDOUT_FD, prog_headers[i].p_addr, 16);

            print_str_literal(STDOUT_FD, "\nFile size: ");
            print_str_num(STDOUT_FD, prog_headers[i].size_in_file, 16);

            print_str_literal(STDOUT_FD, "\nMemory size: ");
            print_str_num(STDOUT_FD, prog_headers[i].size_in_mem, 16);

            print_str_literal(STDOUT_FD, "\nFlags: ");
            print_str_num(STDOUT_FD, prog_headers[i].flags, 2);

            print_str_literal(STDOUT_FD, "\nAlignment: ");
            print_str_num(STDOUT_FD, prog_headers[i].align, 16);

            print_str_literal(STDOUT_FD, "\n");
        }
        print_str_literal(STDOUT_FD, "\n");
    }

    void Parser_64b::print_sh_type(const u16 i) const {
        switch(sect_headers[i].type) {
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
        for (u8 i = 0; i < sh_data.entry_count; i++) {
            print_str_literal(STDOUT_FD, "\n");

            print_str_literal(STDOUT_FD, "Name: ");
            // print_str(STDOUT_FD, sect_headers[i].name);

            print_str_literal(STDOUT_FD, "\nType: ");
            print_sh_type(i);

            print_str_literal(STDOUT_FD, "\nFlags: ");
            print_str_num(STDOUT_FD, sect_headers[i].flags, 2);

            print_str_literal(STDOUT_FD, "\nAddress: ");
            print_str_num(STDOUT_FD, sect_headers[i].addr, 16);

            print_str_literal(STDOUT_FD, "\nOffset: ");
            print_str_num(STDOUT_FD, sect_headers[i].offset, 16);

            print_str_literal(STDOUT_FD, "\nSize: ");
            print_str_num(STDOUT_FD, sect_headers[i].size, 16);

            print_str_literal(STDOUT_FD, "\nLink: ");
            print_str_num(STDOUT_FD, sect_headers[i].link, 16);

            print_str_literal(STDOUT_FD, "\nInfo: ");
            print_str_num(STDOUT_FD, sect_headers[i].info, 16);

            print_str_literal(STDOUT_FD, "\nAddress alignment: ");
            print_str_num(STDOUT_FD, sect_headers[i].align, 16);

            print_str_literal(STDOUT_FD, "\nEntry size: ");
            print_str_num(STDOUT_FD, sect_headers[i].entry_size, 16);

            print_str_literal(STDOUT_FD, "\n");
        }
        print_str_literal(STDOUT_FD, "\n");
    }
#endif

    inline void Parser_64b::check_elf_header_magic(void) {
        u32 magic;
        read_elf_header_data(0x0, 4, &magic);

        if (memcmp(&magic, "\x7F\x45\x4C\x46", 4) != 0) {
            print_str_literal(STDERR_FD, "Not an ELF file\n");
            syscall_exit(1);
        }
    }

    inline void Parser_64b::check_elf_header_class(void) {
        u8 byte_class;
        read_elf_header_data(0x4, 1, &byte_class);

        if (byte_class != 0x2) {
            print_str_literal(STDERR_FD, "ELF file isn't 64 bit. This loader only supports 64 bit.\n");
            syscall_exit(1);
        }
    }

    inline void Parser_64b::read_elf_header_data(const u16 offset, const u8 size, void* data) {
        syscall_lseek(fd, offset, 0);
        syscall_read(fd, reinterpret_cast<char*>(data), size);
    }

    /* Get the ELF file entry point from the ELF header */
    void Parser_64b::parse_elf_header(void) {
        check_elf_header_magic();
        check_elf_header_class();
        read_elf_header_data(0x5, 1, &elf_header.endianness);
        // check_elf_header_osabi();
        read_elf_header_data(0x10, 2, &elf_header.file_type);
        read_elf_header_data(0x12, 1, &elf_header.isa);
        read_elf_header_data(0x18, 8, &elf_header.entry_point);
        read_elf_header_data(0x20, 8, &ph_data.offset);
        read_elf_header_data(0x28, 8, &sh_data.offset);
        read_elf_header_data(0x36, 2, &ph_data.entry_size);
        read_elf_header_data(0x38, 2, &ph_data.entry_count);
        read_elf_header_data(0x3A, 2, &sh_data.entry_size);
        read_elf_header_data(0x3C, 2, &sh_data.entry_count);
        read_elf_header_data(0x3E, 2, &sect_indices.shstrtab_index);
    }

    /* Get the program header data */
    void Parser_64b::parse_prog_headers(void) {
        prog_headers = reinterpret_cast<struct ph_table_ent*>(syscall_mmap(0x0, ph_data.entry_count * sizeof(ph_table_ent),
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));

        for (u16 i = 0; i < ph_data.entry_count; i++) {
            syscall_lseek(fd, ph_data.offset + i * ph_data.entry_size, 0);

            syscall_read(fd, reinterpret_cast<char*>(&prog_headers[i].type), 4); // segment type
            syscall_read(fd, reinterpret_cast<char*>(&prog_headers[i].flags), 4); // segment flags
            syscall_read(fd, reinterpret_cast<char*>(&prog_headers[i].offset), 8); // offset in file
            syscall_read(fd, reinterpret_cast<char*>(&prog_headers[i].v_addr), 8); // virtual address in memory
            syscall_read(fd, reinterpret_cast<char*>(&prog_headers[i].p_addr), 8); // physical address in memory
            syscall_read(fd, reinterpret_cast<char*>(&prog_headers[i].size_in_file), 8); // size of segment in file
            syscall_read(fd, reinterpret_cast<char*>(&prog_headers[i].size_in_mem), 8); // size of segment in memory
            syscall_read(fd, reinterpret_cast<char*>(&prog_headers[i].align), 8); // alignment
            get_segment_data(i);
        }
    }

    /* Get the actual data from the segment a program header is pointing at*/
    void Parser_64b::get_segment_data(const u16 i) {
        if (prog_headers[i].size_in_file == 0) { // segment has no data to read
            return;
        }

        prog_headers[i].data = reinterpret_cast<void*>(syscall_mmap(prog_headers[i].v_addr, prog_headers[i].size_in_mem,
                PROT_WRITE, MAP_PRIVATE, fd, prog_headers[i].offset));

        if (prog_headers[i].data == MAP_FAILED) {
            print_str_literal(STDERR_FD, "mmap failed\n");
            syscall_exit(1);
        }

        if (syscall_mprotect(reinterpret_cast<u64>(prog_headers[i].data), prog_headers[i].size_in_mem,
                elf_perm_to_mmap_perms(prog_headers[i].flags)) == -1) { // after write, change to the correct permissions
            print_str_literal(STDERR_FD, "mprotect failed\n");
            syscall_exit(1);
        }
    }

    void Parser_64b::parse_sect_headers(void) {
        sect_headers = reinterpret_cast<struct sh_table_ent*>(syscall_mmap(0x0, sh_data.entry_count * sizeof(sh_table_ent),
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));

        for (u16 i = 0; i < sh_data.entry_count; i++) {
            syscall_lseek(fd, sh_data.offset + i * sh_data.entry_size, 0);

            syscall_read(fd, reinterpret_cast<char*>(&sect_headers[i].name), 4); // offset into the .shstrtab section
            syscall_read(fd, reinterpret_cast<char*>(&sect_headers[i].type), 4); // type of section
            syscall_read(fd, reinterpret_cast<char*>(&sect_headers[i].flags), 8); // section attributes
            syscall_read(fd, reinterpret_cast<char*>(&sect_headers[i].addr), 8); // virtual address in memory
            syscall_read(fd, reinterpret_cast<char*>(&sect_headers[i].offset), 8); // offset in file
            syscall_read(fd, reinterpret_cast<char*>(&sect_headers[i].size), 8); // size of section
            syscall_read(fd, reinterpret_cast<char*>(&sect_headers[i].link), 4); // index of a related section
            syscall_read(fd, reinterpret_cast<char*>(&sect_headers[i].info), 4); // depends on section type
            syscall_read(fd, reinterpret_cast<char*>(&sect_headers[i].align), 8); // alignment
            syscall_read(fd, reinterpret_cast<char*>(&sect_headers[i].entry_size), 8); // size of each entry if section holds a table

            // get_section_data(i);
        }
    }

    /* Get the offset associated with "str", if its found in the str table specified by "string_table_index". If the string isn't found, the function returns -1*/
    s64 Parser_64b::get_string_offset(const u32 string_table_index, const char* str, const u32 str_len) const {
        for (u32 i = 0; i < sect_headers[string_table_index].size; i++) {
            if (*(reinterpret_cast<char*>(sect_headers[string_table_index].data) + i) == '\0') { // if this is a start of a new string
                if (memcmp(str, reinterpret_cast<char*>(sect_headers[string_table_index].data) + i + 1, str_len) == 0) {
                    return i; // return the offset of the string
                }
            }
        }

        return -1;
    }

    // void Parser_64b::get_section_data(const u16 i) {
    //     static s64 strtab_offset = get_string_offset(".")
    //     switch()
        // if (sect_headers[i].size == 0) { // section has no data to read
        //     return;
        // }

        // sect_headers[i].data = reinterpret_cast<void*>(syscall_mmap(sect_headers[i].addr, sect_headers[i].size,
        //         PROT_WRITE, MAP_PRIVATE, fd, sect_headers[i].offset));

        // if (sect_headers[i].data == MAP_FAILED) {
        //     syscall_write(2, "mmap failed\n", 12);
        //     syscall_exit(1);
        // }

        // if (syscall_mprotect(reinterpret_cast<u64>(sect_headers[i].data), sect_headers[i].size,
        //         elf_perm_to_mmap_perms(sect_headers[i].flags)) == -1) { // after write, change to the correct permissions
        //     syscall_write(2, "mprotect failed\n", 16);
        //     syscall_exit(1);
        // }
    // }
};
