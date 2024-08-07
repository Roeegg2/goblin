#ifndef PARSER_HPP
#define PARSER_HPP

#include <elf.h>

namespace Roee_ELF {
    // struct ph_sh_data {
    //     uint64_t offset; // section/program header table's file offset
    //     uint16_t entry_size; // size of each section/program header table entry
    //     uint16_t entry_count; // number of entries in the section/program header table
    // };

    // struct ph_table_ent {
    //     uint32_t type; // type of segment
    //     uint32_t flags; // segment attributes
    //     uint64_t offset; // offset in file
    //     uint64_t v_addr; // virtual address in memory
    //     uint64_t p_addr; // physical address in memory (mostly unused)
    //     uint64_t size_in_file; // size of segment in file
    //     uint64_t size_in_mem; // size of segment in memory
    //     uint64_t align; // alignment

    //     void* data; // segment data (not part of the ELF file, but used by the loader)
    // };

    // struct sh_table_ent {
    //     uint32_t name; // offset into the .shstrtab section
    //     uint32_t type; // type of section
    //     uint64_t flags; // section attributes
    //     uint64_t addr; // virtual address in memory
    //     uint64_t offset; // offset in file
    //     uint64_t size; // size of section
    //     uint32_t link; // index of a related section
    //     uint32_t info; // depends on section type
    //     uint64_t align; // alignment
    //     uint64_t entry_size; // size of each entry (if section holds a table)

    //     void* data; // section data (not part of the ELF file, but used by the loader)
    // };

    class Parser_64b final {
    public:
        Parser_64b(const char* file_name);
        void init(const char* file_name);
        void parse_elf_header(void);
        void get_section_data(const uint16_t i);
        void parse_prog_headers(void);
        void parse_sect_headers(void);
        int64_t get_string_offset(const uint32_t string_table_index, const char* str, const uint32_t str_len) const;

        inline void check_elf_header_magic(void);
        inline void check_elf_header_class(void);

        void read_elf_header_data(void* data, const uint8_t bytes, const int32_t offset = -1);

#ifdef DEBUG
        void print_file_info(void) const;
        void print_isa(void) const;
        void print_file_type(void) const;

        void print_sect_headers(void) const;
        void print_prog_headers(void) const;

        void print_ph_type(const uint16_t i) const;
        void print_sh_type(const uint16_t i) const;
#endif

    public:
        int elf_file_fd;

        Elf64_Ehdr elf_header;
        Elf64_Phdr* prog_headers;
        Elf64_Shdr* sect_headers;

        struct {
            uint32_t symtab_index;
            uint32_t strtab_index;
            uint32_t shstrtab_index;
        } sect_indices;
    };
}

#endif
