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
            syscall_write(2, "Failed to open file\n", 20);
            syscall_exit(1);
        }
    }

#ifdef DEBUG
    void Parser_64b::print_file_info(void) const {
        syscall_write(1, "ISA: ", 5);
        print_isa();
        syscall_write(1, "File type: ", 11);
        print_file_type();
        syscall_write(1, "Entry point: ", 13);
        syscall_write(1, reinterpret_cast<char*>(elf_header.entry_point), 8);
        syscall_write(1, "\n", 1);
    }

    void Parser_64b::print_isa(void) const {
        switch (elf_header.isa) {
            case 0x0:
                syscall_write(1, "No specific ISA\n", 16);
                break;
            case 0x2:
                syscall_write(1, "SPARC\n", 6);
                break;
            case 0x3:
                syscall_write(1, "x86\n", 4);
                break;
            case 0x8:
                syscall_write(1, "MIPS\n", 5);
                break;
            case 0x14:
                syscall_write(1, "PowerPC\n", 8);
                break;
            case 0x16:
                syscall_write(1, "S390\n", 5);
                break;
            case 0x28:
                syscall_write(1, "ARM\n", 4);
                break;
            case 0x2A:
                syscall_write(1, "SuperH\n", 7);
                break;
            case 0x32:
                syscall_write(1, "IA-64\n", 6);
                break;
            case 0x3E:
                syscall_write(1, "x86-64\n", 7);
                break;
            case 0xB7:
                syscall_write(1, "AArch64\n", 8);
                break;
            case 0xF3:
                syscall_write(1, "RISC-V\n", 7);
                break;
            default:
                syscall_write(1, "Other\n", 6);
                break;

        }
    }

    void Parser_64b::print_file_type(void) const {
        switch (elf_header.file_type) {
            case 0x0:
                syscall_write(1, "No file type\n", 13);
                break;
            case 0x1:
                syscall_write(1, "Relocatable\n", 12);
                break;
            case 0x2:
                syscall_write(1, "Executable\n", 11);
                break;
            case 0x3:
                syscall_write(1, "Shared object\n", 14);
                break;
            case 0x4:
                syscall_write(1, "Core dump\n", 10);
                break;
            default:
                syscall_write(1, "Other\n", 6);
                break;
        }
    }

    void Parser_64b::print_ph_type(const u16 i) const {
        switch (prog_headers[i].type) {
            case PT_NULL:
                syscall_write(1, "Unused program header table entry\n", 34);
                break;
            case PT_LOAD:
                syscall_write(1, "Loadable segment\n", 17);
                break;
            case PT_DYNAMIC:
                syscall_write(1, "Dynamic linking information\n", 28);
                break;
            case PT_INTERP:
                syscall_write(1, "Interpreter information\n", 25);
                break;
            case PT_NOTE:
                syscall_write(1, "Auxiliary information\n", 22);
                break;
            case PT_SHLIB:
                syscall_write(1, "Reserved\n", 9);
                break;
            case PT_PHDR:
                syscall_write(1, "Program header table itself\n", 28);
                break;
            case PT_TLS:
                syscall_write(1, "Thread-local storage template\n", 30);
                break;
            case PT_LOOS:
                syscall_write(1, "OS specific\n", 11);
                break;
            case PT_HIOS:
                syscall_write(1, "OS specific\n", 11);
                break;
            case PT_LOPROC:
                syscall_write(1, "Processor specific\n", 19);
                break;
            case PT_HIPROC:
                syscall_write(1, "Processor specific\n", 19);
                break;
            case PT_GNUEH_FRAME:
                syscall_write(1, "GNU_EH_FRAME\n", 13);
                break;
            case PT_GNUSTACK:
                syscall_write(1, "GNU_STACK\n", 10);
                break;
            case PT_GNU_RELRO:
                syscall_write(1, "GNU_RELRO\n", 10);
                break;
            case PT_GNUPROPERTY:
                syscall_write(1, "GNU_PROPERTY\n", 13);
                break;
            default:
                syscall_write(1, "Unknown\n", 8);
                break;
        }
    }

    void Parser_64b::print_prog_headers(void) const {
        syscall_write(1, "==== Program headers:\n ====", 17);
        for (u8 i = 0; i < ph_data.entry_count; i++) {
            syscall_write(1, "\n", 1);
            syscall_write(1, reinterpret_cast<char*>(NUM_ASCII(i)), 1);
            syscall_write(1, "Type: ", 6);
            print_ph_type(i);
            syscall_write(1, "Offset: ", 8);
            syscall_write(1, reinterpret_cast<char*>(prog_headers[i].offset), 8);
            syscall_write(1, "Virtual address: ", 17);
            syscall_write(1, reinterpret_cast<char*>(prog_headers[i].v_addr), 8);
            syscall_write(1, "Physical address: ", 18);
            syscall_write(1, reinterpret_cast<char*>(prog_headers[i].p_addr), 8);
            syscall_write(1, "File size: ", 11);
            syscall_write(1, reinterpret_cast<char*>(prog_headers[i].size_in_file), 8);
            syscall_write(1, "Memory size: ", 13);
            syscall_write(1, reinterpret_cast<char*>(prog_headers[i].size_in_mem), 8);
            syscall_write(1, "Flags: ", 7);
            syscall_write(1, reinterpret_cast<char*>(prog_headers[i].flags), 8);
            syscall_write(1, "Alignment: ", 11);
            syscall_write(1, reinterpret_cast<char*>(prog_headers[i].align), 8);
            syscall_write(1, "\n", 1);
        }
        syscall_write(1, "\n", 1);
    }

    void Parser_64b::print_sh_type(const u16 i) const {
        switch(sect_headers[i].type) {
            case SHT_NULL:
                syscall_write(1, "NULL\n", 5);
                break;
            case SHT_PROGBITS:
                syscall_write(1, "PROGBITS\n", 9);
                break;
            case SHT_SYMTAB:
                syscall_write(1, "SYMTAB\n", 7);
                break;
            case SHT_STRTAB:
                syscall_write(1, "STRTAB\n", 7);
                break;
            case SHT_RELA:
                syscall_write(1, "RELA\n", 5);
                break;
            case SHT_HASH:
                syscall_write(1, "HASH\n", 5);
                break;
            case SHT_DYNAMIC:
                syscall_write(1, "DYNAMIC\n", 8);
                break;
            case SHT_NOTE:
                syscall_write(1, "NOTE\n", 5);
                break;
            case SHT_NOBITS:
                syscall_write(1, "NOBITS\n", 7);
                break;
            case SHT_REL:
                syscall_write(1, "REL\n", 4);
                break;
            case SHT_SHLIB:
                syscall_write(1, "SHLIB\n", 6);
                break;
            case SHT_DYNSYM:
                syscall_write(1, "DYNSYM\n", 7);
                break;
            case SHT_INIT_ARRAY:
                syscall_write(1, "INIT_ARRAY\n", 11);
                break;
            case SHT_FINI_ARRAY:
                syscall_write(1, "FINI_ARRAY\n", 11);
                break;
            case SHT_PREINIT_ARRAY:
                syscall_write(1, "PREINIT_ARRAY\n", 14);
                break;
            case SHT_GROUP:
                syscall_write(1, "GROUP\n", 6);
                break;
            case SHT_SYMTAB_SHNDX:
                syscall_write(1, "SYMTAB_SHNDX\n", 13);
                break;
            case SHT_LOOS:
                syscall_write(1, "OS specific\n", 11);
                break;
            case SHT_HIOS:
                syscall_write(1, "OS specific\n", 11);
                break;
            case SHT_LOPROC:
                syscall_write(1, "Processor specific\n", 19);
                break;
            case SHT_HIPROC:
                syscall_write(1, "Processor specific\n", 19);
                break;
            case SHT_LOUSER:
                syscall_write(1, "User specific\n", 14);
                break;
            case SHT_HIUSER:
                syscall_write(1, "User specific\n", 14);
                break;
            default:
                syscall_write(1, "Other\n", 6);
                break;
        }
    }

    void Parser_64b::print_sect_headers(void) const {
        syscall_write(1, "==== Section headers:\n ====", 17);
        for (u8 i = 0; i < sh_data.entry_count; i++) {
            syscall_write(1, "\n", 1);
            syscall_write(1, reinterpret_cast<char*>(NUM_ASCII(i)), 1);
            syscall_write(1, "Name: ", 6);
            syscall_write(1, reinterpret_cast<char*>(sect_headers[i].name), 8);
            syscall_write(1, "Type: ", 6);
            print_sh_type(i);
            syscall_write(1, "Flags: ", 7);
            syscall_write(1, reinterpret_cast<char*>(sect_headers[i].flags), 8);
            syscall_write(1, "Address: ", 9);
            syscall_write(1, reinterpret_cast<char*>(sect_headers[i].addr), 8);
            syscall_write(1, "Offset: ", 8);
            syscall_write(1, reinterpret_cast<char*>(sect_headers[i].offset), 8);
            syscall_write(1, "Size: ", 6);
            syscall_write(1, reinterpret_cast<char*>(sect_headers[i].size), 8);
            syscall_write(1, "Link: ", 6);
            syscall_write(1, reinterpret_cast<char*>(sect_headers[i].link), 8);
            syscall_write(1, "Info: ", 6);
            syscall_write(1, reinterpret_cast<char*>(sect_headers[i].info), 8);
            syscall_write(1, "Address alignment: ", 19);
            syscall_write(1, reinterpret_cast<char*>(sect_headers[i].align), 8);
            syscall_write(1, "Entry size: ", 12);
            syscall_write(1, reinterpret_cast<char*>(sect_headers[i].entry_size), 8);
            syscall_write(1, "\n", 1);
        }
        syscall_write(1, "\n", 1);
    }
#endif

    inline void Parser_64b::check_elf_header_magic(void) {
        u32 magic;
        read_elf_header_data(0x0, 4, &magic);

        if (memcmp(&magic, "\x7F\x45\x4C\x46", 4) != 0) {
            syscall_write(2, "Not an ELF file\n", 16);
            syscall_exit(1);
        }
    }

    inline void Parser_64b::check_elf_header_class(void) {
        u8 byte_class;
        read_elf_header_data(0x4, 1, &byte_class);

        if (byte_class != 0x2) {
            syscall_write(2, "ELF file isn't 64 bit. This loader only supports 64 bit.\n", 58);
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
            syscall_write(2, "mmap failed\n", 12);
            syscall_exit(1);
        }

        if (syscall_mprotect(reinterpret_cast<u64>(prog_headers[i].data), prog_headers[i].size_in_mem,
                elf_perm_to_mmap_perms(prog_headers[i].flags)) == -1) { // after write, change to the correct permissions
            syscall_write(2, "mprotect failed\n", 16);
            syscall_exit(1);
        }
    };

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
}
