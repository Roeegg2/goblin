#ifndef PARSER_HPP
#define PARSER_HPP

#include <elf.h>
#include <fstream>

namespace Roee_ELF {
    class Parser_64b {
    public:
        Parser_64b(const char* file_name);
        ~Parser_64b(void);
        void full_parse(void);
        void parse_elf_header(void);
        void parse_prog_headers(void);
        void parse_sect_headers(void);
        void get_section_data(const uint16_t i);

#ifdef DEBUG
        void full_print(void) const;
        void print_file_info(void) const;
        void print_isa(void) const;
        void print_file_type(void) const;

        void print_sect_headers(void) const;
        void print_prog_headers(void) const;

        void print_ph_type(const uint16_t i) const;
        void print_sh_type(const uint16_t i) const;

        void print_symtab(void) const;
#endif
    protected:
        inline void check_elf_header_magic(void);
        inline void check_elf_header_class(void);
        void read_elf_header_data(void* data, const uint8_t bytes, const int32_t offset = -1);

    public:
        std::ifstream elf_file;

        Elf64_Ehdr elf_header;
        Elf64_Phdr* prog_headers;
        Elf64_Shdr* sect_headers;

        int16_t dyn_seg_index;
    };
}

#endif
