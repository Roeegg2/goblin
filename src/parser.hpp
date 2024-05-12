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
    };

    struct prog_header {
        std::string type;
        char flags[4] = { '.', '.', '.', '\0' };
        uint64_t offset; // offset within the file of where the actual segment data resides
        uint64_t virtual_addr; // segments base virtual address
        uint64_t physical_addr; // segments base physical address
        uint64_t size_in_file; // size of the segment in the file
        uint64_t size_in_mem; // size of the segment in memory
        uint64_t align;
    };

    class Parser_64b final {
    public:
        Parser_64b(std::ifstream& file);
        void parse_isa();
        void parse_file_type();
        void parse_entry_point();
        void parse_prog_headers();

    private:
        void parse_prog_header_flags(const uint8_t i);
        void parse_prog_header_type(const uint8_t i);
#ifdef DEBUG
        void print_prog_header(const struct prog_header& ph) const;
#endif

    private:
        std::ifstream& file;

        uint16_t isa;
        uint16_t file_type;
        uint64_t entry_point;
        std::vector<struct prog_header> prog_headers;
    };

}