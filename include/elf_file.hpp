#ifndef GOBLIN_ELF_FILE_HPP
#define GOBLIN_ELF_FILE_HPP

#include <cstdint>
#include <elf.h>
#include <filesystem>
#include <fstream>

namespace Goblin {
class ELF_File {
  public:
    ELF_File(const std::string file_path, const bool full_parse_now = true);
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
    uint16_t get_section_index_by_type(const decltype(Elf64_Shdr::sh_type) type) const;
    uint16_t get_section_index_by_name(const char *name) const;
    Elf64_Sym *get_sym_by_name(Elf64_Sym *symtab, const char *strtab, const char *sym_name, const uint32_t ent_num) const;

  private:
    inline void check_elf_header_magic(void);
    inline void check_elf_header_class(void);
    void read_elf_header_data(void *data, const uint8_t bytes, const int32_t offset = -1);
    Elf64_Word get_section_st_name_by_name(const char *name) const;

  protected:
    std::filesystem::path m_elf_file_path;
    std::ifstream m_elf_file;

    Elf64_Ehdr m_elf_header;
    Elf64_Phdr *m_prog_headers;
    Elf64_Shdr *m_sect_headers;

    char *m_shstrtab;
};
}; // namespace Goblin

#endif
