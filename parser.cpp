#include <iostream>
#include <cstring>

#include "parser.hpp"

namespace Roee_ELF {
    Parser_64b::Parser_64b(std::ifstream& file)
        : file(file) {}

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
        switch (elf_header.e_isa) {
            case 0x0:
                std::cout << "No specific ISA\n\n";
                break;
            case 0x2:
                std::cout << "SPARC\n\n";
                break;
            case 0x3:
                std::cout << "x86\n\n";
                break;
            case 0x8:
                std::cout << "MIPS\n\n";
                break;
            case 0x14:
                std::cout << "PowerPC\n\n";
                break;
            case 0x16:
                std::cout << "S390\n\n";
                break;
            case 0x28:
                std::cout << "ARM\n\n";
                break;
            case 0x2A:
                std::cout << "SuperH\n\n";
                break;
            case 0x32:
                std::cout << "IA-64\n\n";
                break;
            case 0x3E:
                std::cout << "x86-64\n\n";
                break;
            case 0xB7:
                std::cout << "AArch64\n\n";
                break;
            case 0xF3:
                std::cout << "RISC-V\n\n";
                break;
            default:
                std::cout << "Other\n\n";
                break;

        }
    }

    void Parser_64b::print_file_type(void) const {
        switch (elf_header.e_type) {
            case 0x0:
                std::cout << "Unknown\n\n";
                break;
            case 0x1:
                std::cout << "Relocatable\n\n";
                break;
            case 0x2:
                std::cout << "Executable\n\n";
                break;
            case 0x3:
                std::cout << "Shared\n\n";
                break;
            case 0x4:
                std::cout << "Core\n\n";
                break;
            default:
                std::cout << "Other\n\n";
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

    /* Get the ELF file entry point from the ELF header */
    void Parser_64b::parse_elf_header() {
        file.seekg(0x10, std::ios::beg);
        file.read(reinterpret_cast<char*>(&elf_header.e_type), 2);
        file.read(reinterpret_cast<char*>(&elf_header.e_isa), 2);

        file.seekg(0x18, std::ios::beg);
        file.read(reinterpret_cast<char*>(&elf_header.e_entry), 8);
        file.read(reinterpret_cast<char*>(&ph_data.offset), 8);
        file.read(reinterpret_cast<char*>(&sh_data.offset), 8);

        file.seekg(0x36, std::ios::beg);
        file.read(reinterpret_cast<char*>(&ph_data.entry_size), 2);
        file.read(reinterpret_cast<char*>(&ph_data.entry_count), 2);
        file.read(reinterpret_cast<char*>(&sh_data.entry_size), 2);
        file.read(reinterpret_cast<char*>(&sh_data.entry_count), 2);
    }

    /* Get the program header data */
    void Parser_64b::parse_prog_headers() {
        for (uint16_t i = 0; i < ph_data.entry_count; i++) {
            struct ph_table_ent ph_ent;

            file.seekg(ph_data.offset + i * ph_data.entry_size, std::ios::beg);
            file.read(reinterpret_cast<char*>(&ph_ent.type), 4);
            file.read(reinterpret_cast<char*>(&ph_ent.flags), 4);
            file.read(reinterpret_cast<char*>(&ph_ent.offset), 8);
            file.read(reinterpret_cast<char*>(&ph_ent.v_addr), 8);
            file.read(reinterpret_cast<char*>(&ph_ent.p_addr), 8);
            file.read(reinterpret_cast<char*>(&ph_ent.size_in_file), 8);
            file.read(reinterpret_cast<char*>(&ph_ent.size_in_mem), 8);
            file.read(reinterpret_cast<char*>(&ph_ent.align), 8);

            prog_headers.push_back(ph_ent);
        }
    }

    /* Get the actual data from the segment a program header is pointing at*/
    void Parser_64b::get_segment_data(uint64_t* buff, const uint16_t i) {
        if (buff == nullptr) {
            std::cerr << "buff is nullptr\n";
            return;
        }

        file.seekg(prog_headers[i].offset, std::ios::beg);
        file.read((char*)(buff), prog_headers[i].size_in_file);
    };
}