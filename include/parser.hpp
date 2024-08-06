#ifndef PARSER_HPP
#define PARSER_HPP

#include "types.hpp"

namespace Roee_ELF {
    enum PROG_HEADER_TYPES {
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

    enum SECT_HEADER_TYPES {
        SHT_NULL = 0,
        SHT_PROGBITS = 1,
        SHT_SYMTAB = 2,
        SHT_STRTAB = 3,
        SHT_RELA = 4,
        SHT_HASH = 5,
        SHT_DYNAMIC = 6,
        SHT_NOTE = 7,
        SHT_NOBITS = 8,
        SHT_REL = 9,
        SHT_SHLIB = 10,
        SHT_DYNSYM = 11,
        SHT_INIT_ARRAY = 14,
        SHT_FINI_ARRAY = 15,
        SHT_PREINIT_ARRAY = 16,
        SHT_GROUP = 17,
        SHT_SYMTAB_SHNDX = 18,
        SHT_LOOS = 0x60000000,
        SHT_HIOS = 0x6fffffff,
        SHT_LOPROC = 0x70000000,
        SHT_HIPROC = 0x7fffffff,
        SHT_GNU_HASH = 0x6ffffff6,
        SHT_GNU_LIBLIST = 0x6ffffff7,
        SHT_CHECKSUM = 0x6ffffff8,
        SHT_LOUSER = 0x80000000,
        SHT_HIUSER = 0xffffffff,
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
        void* data; // section data
    };

    class Parser_64b final {
    public:
        Parser_64b(const char* file_name);
        void init(const char* file_name);
        void parse_elf_header(void);
        void get_segment_data(const u16 i);
        void get_section_data(const u16 i);
        void parse_prog_headers(void);
        void parse_sect_headers(void);
        u64 get_symbol_value(const char* sym_name, const u32 len);
        u32 find_string_table_ent(const char* sym_name, const u32 len);

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
        struct sh_table_ent* sect_headers;

        u32 symtab_sect_index;
        u32 strtab_sect_index;
    };
}

#endif
