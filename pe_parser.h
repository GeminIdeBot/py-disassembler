#ifndef PE_PARSER_H
#define PE_PARSER_H

#include <cstdint>
#include <string>
#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>

// Define structures for DOS and PE headers
// For simplicity, only relevant fields are included

// DOS Header (IMAGE_DOS_HEADER)
struct IMAGE_DOS_HEADER {
    uint16_t e_magic;    // Magic number
    uint16_t e_cblp;     // Bytes on last page of file
    uint16_t e_cp;       // Pages in file
    uint16_t e_crlc;     // Relocations
    uint16_t e_cparhdr;  // Size of header in paragraphs
    uint16_t e_minalloc; // Minimum extra paragraphs needed
    uint16_t e_maxalloc; // Maximum extra paragraphs needed
    uint16_t e_ss;       // Initial (relative) SS value
    uint16_t e_sp;       // Initial SP value
    uint16_t e_csum;     // Checksum
    uint16_t e_ip;       // Initial IP value
    uint16_t e_cs;       // Initial (relative) CS value
    uint16_t e_lfarlc;   // File address of relocation table
    uint16_t e_ovno;     // Overlay number
    uint16_t e_res[4];   // Reserved words
    uint16_t e_oemid;    // OEM identifier (for e_oeminfo)
    uint16_t e_oeminfo;  // OEM information; e_oemid specific
    uint16_t e_res2[10]; // Reserved words
    uint32_t e_lfanew;   // File address of new exe header
};

// PE Signature
struct PE_SIGNATURE {
    uint32_t Signature; // "PE\0\0"
};

// COFF File Header (IMAGE_FILE_HEADER)
struct IMAGE_FILE_HEADER {
    uint16_t Machine;              // Architecture type
    uint16_t NumberOfSections;     // Number of sections
    uint32_t TimeDateStamp;        // Time and date of compilation
    uint32_t PointerToSymbolTable; // File offset of symbol table
    uint32_t NumberOfSymbols;      // Number of symbols
    uint16_t SizeOfOptionalHeader; // Size of optional header
    uint16_t Characteristics;      // File characteristics
};

// Section Header (IMAGE_SECTION_HEADER)
struct IMAGE_SECTION_HEADER {
    char     Name[8];             // Section name
    uint32_t VirtualSize;         // Total size of the section when loaded into memory
    uint32_t VirtualAddress;      // The address of the first byte of the section, when loaded into memory, relative to the image base
    uint32_t SizeOfRawData;       // The size of the initialized data on disk
    uint32_t PointerToRawData;    // The file pointer to the first page of the initialized data
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

// Optional Header (IMAGE_OPTIONAL_HEADER) - for 32-bit executables (PE32)
struct IMAGE_OPTIONAL_HEADER32 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;    // RVA of entry point
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;              // Preferred base address of the image when loaded
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
};

// Function declaration
void read_exe_header(const std::string& filepath);

#endif // PE_PARSER_H