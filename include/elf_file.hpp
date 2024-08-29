#ifndef PARSER_HPP
#define PARSER_HPP

#include <elf.h>
#include <fstream>
#include <filesystem>
#include <vector>

namespace Goblin {
    class ELF_File {
    public:
        ELF_File(std::string file_path);
        ~ELF_File(void);
        void full_parse(void);
        void parse_elf_header(void);
        void parse_prog_headers(void);
        void parse_sect_headers(void);

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
        std::filesystem::path elf_file_path;
        std::ifstream elf_file;

        Elf64_Ehdr elf_header;
        Elf64_Phdr* prog_headers;
        Elf64_Shdr* sect_headers;
        std::vector<const char*> sect_names;
    };
}

#endif
