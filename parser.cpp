#include <iostream>
#include <cstring>

#include "parser.hpp"

namespace Roee_ELF {
    Parser_64b::Parser_64b(std::ifstream& file)
        : file(file) {}

#ifdef DEBUG
    void Parser_64b::print_prog_header(const struct prog_header& ph) const {
        std::cout << "\nPROG HEADER:\n"
            << "\nType: " << std::hex << ph.type
            << "\nFlags: " << std::hex << ph.flags
            << "\nOffset: 0x" << std::hex << ph.offset
            << "\nVirtual address: 0x" << std::hex << ph.virtual_addr
            << "\nPhysical address: 0x" << std::hex << ph.physical_addr
            << "\nSize in file: 0x" << std::hex << ph.size_in_file
            << "\nSize in memory: 0x" << std::hex << ph.size_in_mem
            << "\nAlign: 0x" << std::hex << ph.align << "\n";
    }

#endif

    void Parser_64b::get_code(uint64_t** code_ptr) const {
        uint16_t code_seg_index;
        for (uint16_t i = 0; i < prog_headers.size(); ++i) {
            if (prog_headers[i].virtual_addr == entry_point) { // if this is the code segment were looking for
                code_seg_index = i;
                goto get_code_seg;
            }
        }

        std::cout << "WARNING: Code segment not found!\n";

    get_code_seg:
        file.seekg(prog_headers[code_seg_index].offset, std::ios::beg);
        file.read((char*)(*code_ptr), 0x100);
    }

    void Parser_64b::parse_prog_header_type(const uint8_t i) {
        uint32_t foo;
        file.read(reinterpret_cast<char*>(&foo), 4);

        switch (foo) {
            case PT_NULL:
                prog_headers[i].type = "Unused program header table entry";
                break;
            case PT_LOAD:
                prog_headers[i].type = "Loadable segment";
                break;
            case PT_DYNAMIC:
                prog_headers[i].type = "Dynamic linking information";
                break;
            case PT_INTERP:
                prog_headers[i].type = "Interpreter information";
                break;
            case PT_NOTE:
                prog_headers[i].type = "Auxiliary information";
                break;
            case PT_SHLIB:
                prog_headers[i].type = "Revserved";
                break;
            case PT_PHDR:
                prog_headers[i].type = "Program header table itself";
                break;
            case PT_TLS:
                prog_headers[i].type = "Thread-local storage template";
                break;
            case PT_LOOS:
                prog_headers[i].type = "OS specific";
                break;
            case PT_HIOS:
                prog_headers[i].type = "OS specific";
                break;
            case PT_LOPROC:
                prog_headers[i].type = "Processor specific";
                break;
            case PT_HIPROC:
                prog_headers[i].type = "Processor specific";
                break;
        }
    }

    void Parser_64b::parse_prog_header_flags(const uint8_t i) {
        uint32_t foo;
        file.read(reinterpret_cast<char*>(&foo), 4);

        if (foo & 0b001)
            prog_headers[i].flags[2] = 'x';
        if (foo & 0b010)
            prog_headers[i].flags[1] = 'w';
        if (foo & 0b100)
            prog_headers[i].flags[0] = 'r';
    }

    void Parser_64b::parse_prog_headers() {
        file.seekg(0x20, std::ios::beg);
        uint64_t ph_offset;
        file.read(reinterpret_cast<char*>(&ph_offset), 8);

        file.seekg(0x36, std::ios::beg);
        uint16_t ph_entry_size;
        file.read(reinterpret_cast<char*>(&ph_entry_size), 2);

        file.seekg(0x38, std::ios::beg);
        uint16_t ph_entry_count;
        file.read(reinterpret_cast<char*>(&ph_entry_count), 2);
        prog_headers.resize(ph_entry_count);

        file.seekg(ph_offset, std::ios::beg);
        for (uint16_t i = 0; i < ph_entry_count; ++i) {
            parse_prog_header_type(i);
            parse_prog_header_flags(i);
            file.read(reinterpret_cast<char*>(&prog_headers[i].offset), 8);
            file.read(reinterpret_cast<char*>(&prog_headers[i].virtual_addr), 8);
            file.read(reinterpret_cast<char*>(&prog_headers[i].physical_addr), 8);
            file.read(reinterpret_cast<char*>(&prog_headers[i].size_in_file), 8);
            file.read(reinterpret_cast<char*>(&prog_headers[i].size_in_mem), 8);
            file.read(reinterpret_cast<char*>(&prog_headers[i].align), 8);
#ifdef DEBUG
            print_prog_header(prog_headers[i]);
#endif
        }
    }

    void Parser_64b::parse_isa() {
        file.seekg(0x12, std::ios::beg);
        file.read(reinterpret_cast<char*>(&isa), 2);

        switch (isa) {
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

    void Parser_64b::parse_file_type() {
        file.seekg(0x10, std::ios::beg);
        file.read(reinterpret_cast<char*>(&file_type), 2);

        switch (file_type) {
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

    void Parser_64b::parse_entry_point() {
        file.seekg(0x18, std::ios::beg);
        file.read(reinterpret_cast<char*>(&entry_point), 8);

        std::cout << "Entry point: 0x" << std::hex << entry_point << "\n";
    }
}