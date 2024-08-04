#ifndef PARSER_HPP
#define PARSER_HPP

#include <cstdint>
#include <fstream>
#include <vector>
#include <string>

namespace Roee_ELF {
    enum PROG_HEADER_TYPE {
        PT_NULL = 0,
        PT_LOAD = 1,
        PT_DYNAMIC = 2,
        PT_INTERP = 3,
        PT_NOTE = 4,
        PT_SHLIB = 5,
        PT_PHDR = 6,
        PT_TLS = 7,
        PT_LOOS = 0x60000000,
        PT_HIOS = 0x6fffffff,
        PT_LOPROC = 0x70000000,
        PT_HIPROC = 0x7fffffff,
        PT_GNUEH_FRAME = 0x6474e550,
        PT_GNUSTACK = 0x6474e551,
        PT_GNU_RELRO = 0x6474e552,
        PT_GNUPROPERTY = 0x6474e553,
    };

    struct ph_sh_data {
        uint64_t offset; // section/program header table's file offset
        uint16_t entry_size; // size of each section/program header table entry
        uint16_t entry_count; // number of entries in the section/program header table
    };

    struct ph_table_ent {
        uint32_t type; // type of segment
        uint32_t flags; // segment attributes
        uint64_t offset; // offset in file
        uint64_t v_addr; // virtual address in memory
        uint64_t p_addr; // physical address in memory (mostly unused)
        uint64_t size_in_file; // size of segment in file
        uint64_t size_in_mem; // size of segment in memory
        uint64_t align; // alignment
        void* data; // segment data
    };

    struct sh_table_ent {
        uint32_t name; // offset into the .shstrtab section
        uint32_t type; // type of section
        uint64_t flags; // section attributes
        uint64_t addr; // virtual address in memory
        uint64_t offset; // offset in file
        uint64_t size; // size of section
        uint32_t link; // index of a related section
        uint32_t info; // depends on section type
        uint64_t align; // alignment
        uint64_t entry_size; // size of each entry if section holds a table
    };

    class Parser_64b final {
    public:
        Parser_64b(const char* file_name);
        void parse_elf_header(void);
        void parse_prog_headers(void);
        void get_segment_data(const uint16_t i);

        inline void check_elf_header_magic(void);
        inline void check_elf_header_class(void);
        inline void read_elf_header_data(uint16_t offset, uint8_t size, void* data);

#ifdef DEBUG
        void print_file_info(void) const;
        void print_isa(void) const;
        void print_file_type(void) const;
        void print_ph_type(const uint8_t i) const;
        void print_ph(void) const;
#endif

    private:
        std::ifstream file;

    public:
        struct ph_sh_data sh_data; // section header table data
        struct ph_sh_data ph_data; // program header table data

        struct {
            uint8_t endianness;
            uint8_t isa;
            uint16_t file_type;
            uint64_t entry_point;
        } elf_header;

        std::vector<struct ph_table_ent> prog_headers;
    };
}

#endif