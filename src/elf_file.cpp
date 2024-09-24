#include "../include/elf_file.hpp"

#include <cstdint>
#include <elf.h>

#include <cstring>
#include <iostream>

namespace Goblin {
ELF_File::ELF_File(const std::string file_path, const bool full_parse_now) : m_elf_file_path(file_path) {
    m_elf_file.open(file_path, std::ios::binary);
    if (!m_elf_file.is_open()) {
        std::cerr << "Failed to open ELF file\n";
        exit(1);
    }

    if (full_parse_now) {
        full_parse();
    }
}

ELF_File::~ELF_File(void) {
    m_elf_file.close();
    delete[] m_prog_headers;
    delete[] m_sect_headers;
    delete[] m_shstrtab;
}

void ELF_File::full_parse(void) {
    parse_elf_header();
    parse_prog_headers();
    parse_sect_headers();

    m_elf_file.seekg(m_sect_headers[m_elf_header.e_shstrndx].sh_offset);
    m_elf_file.read(m_shstrtab, m_sect_headers[m_elf_header.e_shstrndx].sh_size);
}

inline void ELF_File::check_elf_header_magic(void) { // sizeof(ELFMAG)
    read_elf_header_data(&m_elf_header.e_ident, SELFMAG, 0x0);
    if (memcmp(m_elf_header.e_ident, &ELFMAG, SELFMAG) != 0) {
        std::cerr << "Not an ELF file\n";
        exit(1);
    }
}

inline void ELF_File::check_elf_header_class(void) {
    read_elf_header_data(&m_elf_header.e_ident[EI_CLASS], 1);
    if (m_elf_header.e_ident[EI_CLASS] != ELFCLASS64) {
        std::cerr << "ELF file isn't 64 bit. This loadable only supports 64 bit.\n";
        exit(1);
    }
}

void ELF_File::read_elf_header_data(void *data, const uint8_t bytes, const int32_t offset) {
    if (offset >= 0) {
        m_elf_file.seekg(offset, std::ios::beg);
    }
    m_elf_file.read(reinterpret_cast<char *>(data), bytes);
}

/* Get the ELF file entry point from the ELF header */
void ELF_File::parse_elf_header(void) {
    check_elf_header_magic();
    check_elf_header_class();

    read_elf_header_data(&m_elf_header.e_ident[EI_DATA], sizeof(m_elf_header.e_ident[EI_DATA]), 0x5);
    read_elf_header_data(&m_elf_header.e_type, sizeof(m_elf_header.e_type), 0x10);
    read_elf_header_data(&m_elf_header.e_machine, sizeof(m_elf_header.e_machine), 0x12);
    read_elf_header_data(&m_elf_header.e_entry, sizeof(m_elf_header.e_entry), 0x18);
    read_elf_header_data(&m_elf_header.e_phoff, sizeof(m_elf_header.e_phoff), 0x20);
    read_elf_header_data(&m_elf_header.e_shoff, sizeof(m_elf_header.e_shoff), 0x28);
    read_elf_header_data(&m_elf_header.e_phentsize, sizeof(m_elf_header.e_phentsize), 0x36);
    read_elf_header_data(&m_elf_header.e_phnum, sizeof(m_elf_header.e_phnum), 0x38);
    read_elf_header_data(&m_elf_header.e_shentsize, sizeof(m_elf_header.e_shentsize), 0x3a);
    read_elf_header_data(&m_elf_header.e_shnum, sizeof(m_elf_header.e_shnum), 0x3c);
    read_elf_header_data(&m_elf_header.e_shstrndx, sizeof(m_elf_header.e_shstrndx), 0x3e);
}

/* Get the program header data */
void ELF_File::parse_prog_headers(void) {
    m_prog_headers = new Elf64_Phdr[m_elf_header.e_phnum];

    for (uint16_t i = 0; i < m_elf_header.e_phnum; i++) {
        m_elf_file.seekg(m_elf_header.e_phoff + i * m_elf_header.e_phentsize);

        m_elf_file.read(reinterpret_cast<char *>(&m_prog_headers[i].p_type),
                        4); // segment type
        m_elf_file.read(reinterpret_cast<char *>(&m_prog_headers[i].p_flags),
                        4); // segment flags
        m_elf_file.read(reinterpret_cast<char *>(&m_prog_headers[i].p_offset),
                        8); // offset in file
        m_elf_file.read(reinterpret_cast<char *>(&m_prog_headers[i].p_vaddr),
                        8); // virtual address in memory
        m_elf_file.read(reinterpret_cast<char *>(&m_prog_headers[i].p_paddr),
                        8); // physical address in memory
        m_elf_file.read(reinterpret_cast<char *>(&m_prog_headers[i].p_filesz),
                        8); // size of segment in file
        m_elf_file.read(reinterpret_cast<char *>(&m_prog_headers[i].p_memsz),
                        8); // size of segment in memory
        m_elf_file.read(reinterpret_cast<char *>(&m_prog_headers[i].p_align),
                        8); // alignment
    }
}

void ELF_File::parse_sect_headers(void) {
    m_sect_headers = new Elf64_Shdr[m_elf_header.e_shnum];

    for (uint16_t i = 0; i < m_elf_header.e_shnum; i++) {
        m_elf_file.seekg(m_elf_header.e_shoff + i * m_elf_header.e_shentsize);

        m_elf_file.read(reinterpret_cast<char *>(&m_sect_headers[i].sh_name),
                        4); // offset into the .shstrtab section
        m_elf_file.read(reinterpret_cast<char *>(&m_sect_headers[i].sh_type),
                        4); // type of section
        m_elf_file.read(reinterpret_cast<char *>(&m_sect_headers[i].sh_flags),
                        8); // section attributes
        m_elf_file.read(reinterpret_cast<char *>(&m_sect_headers[i].sh_addr),
                        8); // virtual address in memory
        m_elf_file.read(reinterpret_cast<char *>(&m_sect_headers[i].sh_offset),
                        8); // offset in file
        m_elf_file.read(reinterpret_cast<char *>(&m_sect_headers[i].sh_size),
                        8); // size of section
        m_elf_file.read(reinterpret_cast<char *>(&m_sect_headers[i].sh_link),
                        4); // index of a related section
        m_elf_file.read(reinterpret_cast<char *>(&m_sect_headers[i].sh_info),
                        4); // depends on section type
        m_elf_file.read(reinterpret_cast<char *>(&m_sect_headers[i].sh_addralign),
                        8); // alignment
        m_elf_file.read(reinterpret_cast<char *>(&m_sect_headers[i].sh_entsize),
                        8); // size of each entry if section holds a table
    }

    m_shstrtab =
        new char[m_sect_headers[m_elf_header.e_shstrndx].sh_size]; // currently isnt used by anyone other than Executable when setting up
                                                                   // main args, but it might be used in the future in loadables too i guess
}

uint16_t ELF_File::get_section_index_by_type(const decltype(Elf64_Shdr::sh_type) type) const {
    for (uint16_t i = 0; i < m_elf_header.e_shnum; i++) {
        if (m_sect_headers[i].sh_type == type) {
            return i;
        }
    }

    return (uint16_t)(-1);
}

Elf64_Word ELF_File::get_section_st_name_by_name(const char *name) const {
    char *shstrtab = m_shstrtab + 1;
    for (uint16_t i = 0; i < m_elf_header.e_shnum; i++) {
        if (std::strcmp(name, shstrtab) == 0) {
            return shstrtab - m_shstrtab;
        }
        shstrtab += std::strlen(shstrtab) + 1;
    }

    return (uint16_t)(-1);
}

uint16_t ELF_File::get_section_index_by_name(const char *name) const { // OPT: check byte-byte instead of having to call strcmp and strlen
    Elf64_Word st_name = get_section_st_name_by_name(name);
    for (uint16_t i = 0; i < m_elf_header.e_shnum; i++) {
        if (m_sect_headers[i].sh_name == st_name) {
            return i;
        }
    }

    return (uint16_t)(-1);
}

Elf64_Sym *ELF_File::get_sym_by_name(Elf64_Sym *symtab, const char *strtab, const char *sym_name, const uint32_t ent_num) const {
    for (uint32_t i = 0; i < ent_num; i++) {
        if (std::strcmp(strtab + symtab[i].st_name, sym_name) == 0) {
            return symtab + i;
        }
    }

    return nullptr;
}
}; // namespace Goblin
