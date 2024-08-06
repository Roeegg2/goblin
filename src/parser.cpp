// #include <iostream>
// #include <cstring>
// #include <sys/mman.h>

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

    void Parser_64b::print_ph_type(const u8 i) const {
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

    // void Parser_64b::print_ph(void) const {
    //     for (u16 i = 0; i < prog_headers.size(); i++) {
    //         std::cout << "Segment " << i
    //             << "  Type: ";
    //         print_ph_type(i);

    //         std::cout << "  Flags: " << std::hex << prog_headers[i].flags
    //             << "  Offset: " << prog_headers[i].offset
    //             << "  Virtual address: " << prog_headers[i].v_addr
    //             << "  Physical address: " << prog_headers[i].p_addr
    //             << "  Size in file: " << prog_headers[i].size_in_file
    //             << "  Size in memory: " << prog_headers[i].size_in_mem
    //             << "  Alignment: " << prog_headers[i].align;
    //     }
    // }
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

    // inline void Parser_64b::check_elf_header_osabi(void) {
    //     uint
    //     read_elf_header_data(0x7, 1, &elf_header.osabi);
    //     if (elf_header.osabi != 0x3) {
    //         std::cerr << "ELF file isn't Linux. This loader only supports Linux.\n";
    //         exit(1);
    //     }
    // }

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

            // prog_headers[i].data = reinterpret_cast<void*>(syscall_mmap(prog_headers[i].v_addr, prog_headers[i].size_in_mem,
                // elf_perm_to_mmap_perms(prog_headers[i].flags), 0x22, fd, prog_headers[i].offset)); // mmapping with PROT_WRITE because we're going to write to it

        if (prog_headers[i].type == PT_LOAD) {
            prog_headers[i].data = reinterpret_cast<void*>(syscall_mmap(prog_headers[i].v_addr, prog_headers[i].size_in_mem,
                PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)); // mmapping with PROT_WRITE because we're going to write to it

            if (prog_headers[i].data == MAP_FAILED) {
                syscall_write(2, "mmap failed\n", 12);
                syscall_exit(1);
            }

            syscall_lseek(fd, prog_headers[i].offset, 0);
            syscall_read(fd, reinterpret_cast<char*>(prog_headers[i].data), prog_headers[i].size_in_file);

            if (syscall_mprotect(reinterpret_cast<u64>(prog_headers[i].data), prog_headers[i].size_in_mem,
                    elf_perm_to_mmap_perms(prog_headers[i].flags)) == -1) { // after write, change to the correct permissions
                syscall_write(2, "mprotect failed\n", 16);
                syscall_exit(1);
            }

        } else {
            // prog_headers[i].data = reinterpret_cast<void*>(0x0, prog_headers[i].size_in_mem,
                // PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); // mmapping with PROT_WRITE because we're going to write to it
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

            get_section_data(i);
        }
    }

    void Parser_64b::get_section_data(const u16 i) {
        switch(sect_headers[i].type) {
            case SHT_SYMTAB:
                symtab_sect_index = i;
                break;
            case SHT_STRTAB:
                strtab_sect_index = i;
                break;
            default:
                sect_headers[i].data = reinterpret_cast<void*>(0x0);
                goto end;
        }

        sect_headers[i].data = reinterpret_cast<void*>(syscall_mmap(0x0, sect_headers[i].size,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));

        syscall_lseek(fd, sect_headers[i].offset, 0);
        syscall_read(fd, reinterpret_cast<char*>(sect_headers[i].data), sect_headers[i].size);

    end:
        return;

    };

    u32 Parser_64b::find_string_table_ent(const char* sym_name, const u32 len) {
        for (u16 i = 0; i < sect_headers[strtab_sect_index].size; i++) {
            if (*(reinterpret_cast<char*>(sect_headers[strtab_sect_index].data) + i) == '\0') { // if we reached the end of some string, that means we're at the beginning of the next string
                if (memcmp(reinterpret_cast<char*>(sect_headers[strtab_sect_index].data + i + 1), sym_name, len) == 0) { // +1 to skip the null byte
                    return i + 1; // return offset of the string
                }
            }
        }

        syscall_write(2, "Failed to find string table entry\n", 34);

        return 0;
    }

    u64 Parser_64b::get_symbol_value(const char* sym_name, const u32 len) {
        u32 sym_name_offset = find_string_table_ent(sym_name, len);

        u64 symbol_count = sect_headers[symtab_sect_index].size / sect_headers[symtab_sect_index].entry_size;
        for (u16 i = 0; i < symbol_count; i += sect_headers[symtab_sect_index].entry_size) {
            if (memcmp(reinterpret_cast<char*>(sect_headers[symtab_sect_index].data + i), &sym_name_offset, 4) == 0) { // +0x10 to skip the first 16 bytes of the symbol table entry
                // u64 symbol_addr;
                // memcpy(&symbol_addr, reinterpret_cast<char*>(sect_headers[symtab_sect_index].data + i), 8);
                // return symbol_addr;
                syscall_write(1, "Found main symbol: ", 19);
                syscall_write(1, reinterpret_cast<char*>(sect_headers[symtab_sect_index].data + i + 0x10), 8);
                return *reinterpret_cast<u64*>(sect_headers[symtab_sect_index].data + i + 0x10);
            }
        }

        syscall_write(2, "Failed to find main symbol\n", 28);

        return 0;
    }
}
