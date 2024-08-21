#ifdef DEBUG
#include "../include/elf_file.hpp"
#include "../include/loadable.hpp"

#include <iostream>
#include <vector>
#include <string>

namespace Roee_ELF {
    void ELF_File::full_print() const {
        print_file_info();
        print_prog_headers();
        print_sect_headers();
        // print_symtab();
    }

    void ELF_File::print_file_info() const {
        std::cout << "ISA: ";
        print_isa();
        std::cout << "\nFile type: ";
        print_file_type();
        std::cout << "\nEntry point: 0x" << std::hex << elf_header.e_entry;
    }

    void ELF_File::print_isa() const {
        static const std::vector<std::string> isa_names = {
            "No specific ISA", "SPARC", "x86", "MIPS", "PowerPC", "S390", "ARM", "SuperH", "IA-64", "x86-64", "AArch64", "RISC-V", "Other"
        };
        std::cout << isa_names[elf_header.e_machine];
    }

    void ELF_File::print_file_type() const {
        static const std::vector<std::string> file_types = { "NONE", "REL", "EXEC", "DYN", "CORE", "OTHER" };
        std::cout << file_types[elf_header.e_type];
    }

    void ELF_File::print_ph_type(uint16_t i) const {
        static const std::vector<std::string> ph_types = {
            "NULL", "LOAD", "DYNAMIC", "INTERP", "NOTE", "SHLIB", "PHDR", "TLS", "LOOS", "HIOS", "LOPROC", "HIPROC",
            "GNUEH_FRAME", "GNU_STACK", "GNU_RELRO", "GNU_PROPERTY", "Unknown", "GNU SHIT"
        };
        std::cout << (prog_headers[i].p_type > 17 ? ph_types[17] : ph_types[prog_headers[i].p_type]);
    }

    void ELF_File::print_prog_headers() const {
        std::cout << "\n==== Program headers: ====\n";
        for (uint8_t i = 0; i < elf_header.e_phnum; i++) {
            std::cout << "Type: ";
            print_ph_type(i);
            std::cout << ", Flags: 0x" << std::hex << prog_headers[i].p_flags
                      << ", Offset: 0x" << prog_headers[i].p_offset
                      << ", Virtual address: 0x" << prog_headers[i].p_vaddr
                      << ", Physical address: 0x" << prog_headers[i].p_paddr
                      << ", File size: 0x" << prog_headers[i].p_filesz
                      << ", Memory size: 0x" << prog_headers[i].p_memsz
                      << ", Alignment: 0x" << prog_headers[i].p_align << "\n";
        }
    }

    void ELF_File::print_sh_type(uint16_t i) const {
        static const std::vector<std::string> sh_types = {
            "NULL", "PROGBITS", "SYMTAB", "STRTAB", "RELA", "HASH", "DYNAMIC", "NOTE", "NOBITS", "REL", "SHLIB", "DYNSYM",
            "INIT_ARRAY", "FINI_ARRAY", "PREINIT_ARRAY", "GROUP", "SYMTAB_SHNDX", "OS specific", "OS specific",
            "Processor specific", "Processor specific", "User specific", "User specific", "Other", "GNU shit"
        };
        std::cout << (sect_headers[i].sh_type > 30 ? sh_types[30] : sh_types[sect_headers[i].sh_type]);
    }

    void ELF_File::print_sect_headers() const {
        std::cout << "\n==== Section headers: ====\n";
        for (uint8_t i = 0; i < elf_header.e_shnum; i++) {
            std::cout << "Name: "; // print_str(STDOUT_FD, sect_headers[i].name);
            std::cout << ", Type: ";
            print_sh_type(i);
            std::cout << ", Flags: 0x" << std::hex << sect_headers[i].sh_flags
                      << ", Address: 0x" << sect_headers[i].sh_addr
                      << ", Offset: 0x" << sect_headers[i].sh_offset
                      << ", Size: 0x" << sect_headers[i].sh_size
                      << ", Link: 0x" << sect_headers[i].sh_link
                      << ", Info: 0x" << sect_headers[i].sh_info
                      << ", Address alignment: 0x" << sect_headers[i].sh_entsize
                      << ", Entry size: 0x" << sect_headers[i].sh_entsize << "\n";
        }
    }

    void Loadable::print_dynamic_segment() const {
        if (dyn_seg_index == -1) {
#ifdef DEBUG
            std::cout << "\nNo dynamic segment found\n";
#endif
            return;
        }

        Elf64_Dyn* dynamic_entries = reinterpret_cast<Elf64_Dyn*>(segment_data[dyn_seg_index]);
        std::cout << "\n==== Dynamic segment: ====\n";
        while (dynamic_entries->d_tag != DT_NULL) {
            print_dynamic_tag(dynamic_entries->d_tag);
            std::cout << ": 0x" << std::hex << dynamic_entries->d_un.d_val << "\n";
            dynamic_entries++;
        }
    }

    void Loadable::print_dynamic_tag(Elf64_Sxword tag) const {
        if (dyn_seg_index == -1) {
#ifdef DEBUG
            std::cout << "No dynamic segment found\n";
#endif
            return;
        }

        static const std::vector<std::string> dynamic_tags = {
            "NULL", "NEEDED", "PLTRELSZ", "PLTGOT", "HASH", "STRTAB", "SYMTAB", "RELA", "RELASZ", "RELAENT", "STRSZ", "SYMENT",
            "INIT", "FINI", "SONAME", "RPATH", "SYMBOLIC", "REL", "RELSZ", "RELENT", "PLTREL", "DEBUG", "TEXTREL", "JMPREL",
            "BIND_NOW", "INIT_ARRAY", "FINI_ARRAY", "INIT_ARRAYSZ", "FINI_ARRAYSZ", "RUNPATH", "FLAGS", "ENCODING", "PREINIT_ARRAY",
            "PREINIT_ARRAYSZ", "MAX"
        };
        std::cout << (tag > 34 ? dynamic_tags[34] : dynamic_tags[tag]);
    }
}
#endif
