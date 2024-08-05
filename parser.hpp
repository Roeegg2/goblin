#ifndef PARSER_HPP
#define PARSER_HPP

#include "types.hpp"

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
        u64 offset; // section/program header table's file offset
        u16 entry_size; // size of each section/program header table entry
        u16 entry_count; // number of entries in the section/program header table
    };

    struct ph_table_ent {
        u32 type; // type of segment
        u32 flags; // segment attributes
        u64 offset; // offset in file
        u64 v_addr; // virtual address in memory
        u64 p_addr; // physical address in memory (mostly unused)
        u64 size_in_file; // size of segment in file
        u64 size_in_mem; // size of segment in memory
        u64 align; // alignment
        void* data; // segment data
    };

    struct sh_table_ent {
        u32 name; // offset into the .shstrtab section
        u32 type; // type of section
        u64 flags; // section attributes
        u64 addr; // virtual address in memory
        u64 offset; // offset in file
        u64 size; // size of section
        u32 link; // index of a related section
        u32 info; // depends on section type
        u64 align; // alignment
        u64 entry_size; // size of each entry if section holds a table
    };

    class Parser_64b final {
    public:
        Parser_64b(const char* file_name);
        void init(const char* file_name);
        void parse_elf_header(void);
        void parse_prog_headers(void);
        void get_segment_data(const u16 i);

        inline void check_elf_header_magic(void);
        inline void check_elf_header_class(void);
        inline void read_elf_header_data(u16 offset, u8 size, void* data);

#ifdef DEBUG
        void print_file_info(void) const;
        void print_isa(void) const;
        void print_file_type(void) const;
        void print_ph_type(const u8 i) const;
        void print_ph(void) const;
#endif

    private:
        // std::ifstream file;
        int fd;

    public:
        struct ph_sh_data sh_data; // section header table data
        struct ph_sh_data ph_data; // program header table data

        struct {
            u8 endianness;
            u8 isa;
            u16 file_type;
            u64 entry_point;
        } elf_header;

        // std::vector<struct ph_table_ent> prog_headers;
        struct ph_table_ent* prog_headers;
    };
}

#endif