#include <iostream>
#include <cstring>
#include <sys/mman.h>

#include "parser.hpp"
#include "utils.hpp"

namespace Roee_ELF {
    Parser_64b::Parser_64b(const char* file_name)
        : file(file_name, std::ios::binary) {
        if (!file.is_open()) {
            std::cerr << "Failed to open file\n";
            exit(1);
        }
    }

#ifdef DEBUG
    void Parser_64b::print_file_info(void) const {
        std::cout << "ISA: ";
        print_isa();
        std::cout << "File type: ";
        print_file_type();
        std::cout << "Entry point: " << std::hex << elf_header.entry_point << std::dec << "\n";

    }

    // void Parser_64b::print_osabi(void) const {
    //     switch (elf_header.osabi) {
    //         case 0x0:
    //             std::cout << "System V\n";
    //             break;
    //         case 0x1:
    //             std::cout << "HP-UX\n";
    //             break;
    //         case 0x2:
    //             std::cout << "NetBSD\n";
    //             break;
    //         case 0x3:
    //             std::cout << "Linux\n";
    //             break;
    //         case 0x6:
    //             std::cout << "Sun Solaris\n";
    //             break;
    //         case 0x7:
    //             std::cout << "AIX\n";
    //             break;
    //         case 0x8:
    //             std::cout << "IRIX\n";
    //             break;
    //         case 0x9:
    //             std::cout << "FreeBSD\n";
    //             break;
    //         case 0xC:
    //             std::cout << "OpenBSD\n";
    //             break;
    //         case 0xE:
    //             std::cout << "OpenVMS\n";
    //             break;
    //         default:
    //             std::cout << "Other\n";
    //             break;
    //     }
    // }

    void Parser_64b::print_ph_type(const uint8_t i) const {
        switch (prog_headers[i].type) {
            case PT_NULL:
                std::cout << "Unused program header table entry\n";
                break;
            case PT_LOAD:
                std::cout << "Loadable segment\n";
                break;
            case PT_DYNAMIC:
                std::cout << "Dynamic linking information\n";
                break;
            case PT_INTERP:
                std::cout << "Interpreter information\n";
                break;
            case PT_NOTE:
                std::cout << "Auxiliary information\n";
                break;
            case PT_SHLIB:
                std::cout << "Revserved\n";
                break;
            case PT_PHDR:
                std::cout << "Program header table itself\n";
                break;
            case PT_TLS:
                std::cout << "Thread-local storage template\n";
                break;
            case PT_LOOS:
                std::cout << "OS specific\n";
                break;
            case PT_HIOS:
                std::cout << "OS specific\n";
                break;
            case PT_LOPROC:
                std::cout << "Processor specific\n";
                break;
            case PT_HIPROC:
                std::cout << "Processor specific\n";
                break;
            case PT_GNUEH_FRAME:
                std::cout << "GNU_EH_FRAME\n";
                break;
            case PT_GNUSTACK:
                std::cout << "GNU_STACK\n";
                break;
            case PT_GNU_RELRO:
                std::cout << "GNU_RELRO\n";
                break;
            case PT_GNUPROPERTY:
                std::cout << "GNU_PROPERTY\n";
                break;
            default:
                std::cout << "Unknown\n";
                break;
        }
    }

    void Parser_64b::print_isa(void) const {
        switch (elf_header.isa) {
            case 0x0:
                std::cout << "No specific ISA\n";
                break;
            case 0x2:
                std::cout << "SPARC\n";
                break;
            case 0x3:
                std::cout << "x86\n";
                break;
            case 0x8:
                std::cout << "MIPS\n";
                break;
            case 0x14:
                std::cout << "PowerPC\n";
                break;
            case 0x16:
                std::cout << "S390\n";
                break;
            case 0x28:
                std::cout << "ARM\n";
                break;
            case 0x2A:
                std::cout << "SuperH\n";
                break;
            case 0x32:
                std::cout << "IA-64\n";
                break;
            case 0x3E:
                std::cout << "x86-64\n";
                break;
            case 0xB7:
                std::cout << "AArch64\n";
                break;
            case 0xF3:
                std::cout << "RISC-V\n";
                break;
            default:
                std::cout << "Other\n";
                break;

        }
    }

    void Parser_64b::print_file_type(void) const {
        switch (elf_header.file_type) {
            case 0x0:
                std::cout << "Unknown\n";
                break;
            case 0x1:
                std::cout << "Relocatable\n";
                break;
            case 0x2:
                std::cout << "Executable\n";
                break;
            case 0x3:
                std::cout << "Shared\n";
                break;
            case 0x4:
                std::cout << "Core\n";
                break;
            default:
                std::cout << "Other\n";
                break;
        }
    }

    void Parser_64b::print_ph(void) const {
        for (uint16_t i = 0; i < prog_headers.size(); i++) {
            std::cout << "Segment " << i
                << "  Type: ";
            print_ph_type(i);

            std::cout << "  Flags: " << std::hex << prog_headers[i].flags
                << "  Offset: " << prog_headers[i].offset
                << "  Virtual address: " << prog_headers[i].v_addr
                << "  Physical address: " << prog_headers[i].p_addr
                << "  Size in file: " << prog_headers[i].size_in_file
                << "  Size in memory: " << prog_headers[i].size_in_mem
                << "  Alignment: " << prog_headers[i].align;
        }
    }
#endif

    inline void Parser_64b::check_elf_header_magic(void) {
        uint32_t magic;
        read_elf_header_data(0x0, 4, &magic);

        if (std::memcmp(&magic, "\x7F\x45\x4C\x46", 4) != 0) {
            std::cerr << "Not an ELF file\n";
            exit(1);
        }
    }

    inline void Parser_64b::check_elf_header_class(void) {
        uint8_t byte_class;
        read_elf_header_data(0x4, 1, &byte_class);

        if (byte_class != 0x2) {
            std::cerr << "ELF file isn't 64 bit. This loader only supports 64 bit.\n";
            exit(1);
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

    inline void Parser_64b::read_elf_header_data(const uint16_t offset, const uint8_t size, void* data) {
        file.seekg(offset, std::ios::beg);
        file.read(reinterpret_cast<char*>(data), size);
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
        prog_headers.reserve(ph_data.entry_count);
        for (uint16_t i = 0; i < ph_data.entry_count; i++) {
            file.seekg(ph_data.offset + i * ph_data.entry_size, std::ios::beg);

            file.read(reinterpret_cast<char*>(&prog_headers[i].type), 4); // segment type
            file.read(reinterpret_cast<char*>(&prog_headers[i].flags), 4); // segment flags 
            file.read(reinterpret_cast<char*>(&prog_headers[i].offset), 8); // offset in file
            file.read(reinterpret_cast<char*>(&prog_headers[i].v_addr), 8); // virtual address in memory
            file.read(reinterpret_cast<char*>(&prog_headers[i].p_addr), 8); // physical address in memory
            file.read(reinterpret_cast<char*>(&prog_headers[i].size_in_file), 8); // size of segment in file
            file.read(reinterpret_cast<char*>(&prog_headers[i].size_in_mem), 8); // size of segment in memory
            file.read(reinterpret_cast<char*>(&prog_headers[i].align), 8); // alignment
            get_segment_data(i);
        }
    }

    /* Get the actual data from the segment a program header is pointing at*/
    void Parser_64b::get_segment_data(const uint16_t i) {
        if (prog_headers[i].size_in_file == 0) { // segment has no data to read
            return;
        }

        if (prog_headers[i].type == PT_LOAD) {
            prog_headers[i].data = mmap(reinterpret_cast<void(*)>(prog_headers[i].v_addr), prog_headers[i].size_in_mem, 
                PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); // mmapping with PROT_WRITE because we're going to write to it

            if (prog_headers[i].data == MAP_FAILED) {
                std::cerr << "mmap failed: error " << errno << std::endl;
                exit(1);
            }
        }
        else {
            prog_headers[i].data = new char[prog_headers[i].size_in_file];
        }

        file.seekg(prog_headers[i].offset, std::ios::beg);
        file.read(reinterpret_cast<char*>(prog_headers[i].data), prog_headers[i].size_in_file);

        if (mprotect(prog_headers[i].data, prog_headers[i].size_in_mem, 
                elf_perm_to_mmap_perms(prog_headers[i].flags)) == -1) { // after write, change to the correct permissions
            std::cerr << "mprotect failed: error " << errno << std::endl;
        }

    };
}