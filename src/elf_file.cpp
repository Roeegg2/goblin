#include "../include/elf_file.hpp"

#include <elf.h>
#include <iostream>
#include <cstring>

#define MAP_SEGMENT_DATA(sect_data, sect_index) \
    mmap_wrapper(reinterpret_cast<void**>(&sect_data), 0x0, sect_headers[sect_index].sh_size, PROT_READ, \
        MAP_PRIVATE, elf_file_fd, PAGE_ALIGN_DOWN(sect_headers[sect_index].sh_offset));

namespace Goblin {
    ELF_File::ELF_File(const std::string file_path) : elf_file_path(file_path){
        elf_file.open(file_path, std::ios::binary);
        if (!elf_file.is_open()) {
            std::cerr << "Failed to open ELF file\n";
            exit(1);
        }
    }

    ELF_File::~ELF_File(void) {
        elf_file.close();
        delete[] prog_headers;
        delete[] sect_headers;
    }

    void ELF_File::full_parse(void) {
        parse_elf_header();
        parse_prog_headers();
        parse_sect_headers();
    }

    inline void ELF_File::check_elf_header_magic(void) { // sizeof(ELFMAG)
        read_elf_header_data(&elf_header.e_ident, SELFMAG, 0x0);
        if (memcmp(elf_header.e_ident, &ELFMAG, SELFMAG) != 0) {
            std::cerr << "Not an ELF file\n";
            exit(1);
        }
    }

    inline void ELF_File::check_elf_header_class(void) {
        read_elf_header_data(&elf_header.e_ident[EI_CLASS], 1);
        if (elf_header.e_ident[EI_CLASS] != ELFCLASS64) {
            std::cerr << "ELF file isn't 64 bit. This loadable only supports 64 bit.\n";
            exit(1);
        }
    }

    void ELF_File::read_elf_header_data(void* data, const uint8_t bytes, const int32_t offset) {
        if (offset >= 0) {
            elf_file.seekg(offset, std::ios::beg);
        }
        elf_file.read(reinterpret_cast<char*>(data), bytes);
    }

    /* Get the ELF file entry point from the ELF header */
    void ELF_File::parse_elf_header(void) {
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
    void ELF_File::parse_prog_headers(void) {
        prog_headers = new Elf64_Phdr[elf_header.e_phnum];

        for (uint16_t i = 0; i < elf_header.e_phnum; i++) {
            elf_file.seekg(elf_header.e_phoff + i * elf_header.e_phentsize);

            elf_file.read(reinterpret_cast<char*>(&prog_headers[i].p_type), 4); // segment type
            elf_file.read(reinterpret_cast<char*>(&prog_headers[i].p_flags), 4); // segment flags
            elf_file.read(reinterpret_cast<char*>(&prog_headers[i].p_offset), 8); // offset in file
            elf_file.read(reinterpret_cast<char*>(&prog_headers[i].p_vaddr), 8); // virtual address in memory
            elf_file.read(reinterpret_cast<char*>(&prog_headers[i].p_paddr), 8); // physical address in memory
            elf_file.read(reinterpret_cast<char*>(&prog_headers[i].p_filesz), 8); // size of segment in file
            elf_file.read(reinterpret_cast<char*>(&prog_headers[i].p_memsz), 8); // size of segment in memory
            elf_file.read(reinterpret_cast<char*>(&prog_headers[i].p_align), 8); // alignment
        }
    }

    void ELF_File::parse_sect_headers(void) {
        sect_headers = new Elf64_Shdr[elf_header.e_shnum];

        for (uint16_t i = 0; i < elf_header.e_shnum; i++) {
            elf_file.seekg(elf_header.e_shoff + i * elf_header.e_shentsize);

            elf_file.read(reinterpret_cast<char*>(&sect_headers[i].sh_name), 4); // offset into the .shstrtab section
            elf_file.read(reinterpret_cast<char*>(&sect_headers[i].sh_type), 4); // type of section
            elf_file.read(reinterpret_cast<char*>(&sect_headers[i].sh_flags), 8); // section attributes
            elf_file.read(reinterpret_cast<char*>(&sect_headers[i].sh_addr), 8); // virtual address in memory
            elf_file.read(reinterpret_cast<char*>(&sect_headers[i].sh_offset), 8); // offset in file
            elf_file.read(reinterpret_cast<char*>(&sect_headers[i].sh_size), 8); // size of section
            elf_file.read(reinterpret_cast<char*>(&sect_headers[i].sh_link), 4); // index of a related section
            elf_file.read(reinterpret_cast<char*>(&sect_headers[i].sh_info), 4); // depends on section type
            elf_file.read(reinterpret_cast<char*>(&sect_headers[i].sh_addralign), 8); // alignment
            elf_file.read(reinterpret_cast<char*>(&sect_headers[i].sh_entsize), 8); // size of each entry if section holds a table
        }
    }

    unsigned long ELF_File::elf_hash(const unsigned char* name) {
        unsigned long hash = 0;
        unsigned long g;

        while (*name) {
            hash = (hash << 4) + *name++;
            g = hash & 0xF0000000;
            if (g != 0)
                hash ^= g >> 24;
            hash &= ~g;
        }

        return hash;
    }

    unsigned long ELF_File::gnu_hash(const unsigned char *name) {
        unsigned long h = 5381;

        for (unsigned char c = *name; c != '\0'; c = *++name) {
            h = (h << 5) + h + c;
        }

        return h;
    }
};
