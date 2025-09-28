#include "pe_parser.h"
#include "x86_decoder.h" // Include the x86 decoder header

void read_exe_header(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);

    if (!file.is_open()) {
        std::cerr << "Ошибка: Не удалось открыть файл " << filepath << std::endl;
        return;
    }

    IMAGE_DOS_HEADER dos_header;
    file.read(reinterpret_cast<char*>(&dos_header), sizeof(IMAGE_DOS_HEADER));

    if (dos_header.e_magic != 0x5A4D) { // 'MZ' in little-endian
        std::cerr << "Неверный формат EXE: Отсутствует 'MZ' заголовок DOS." << std::endl;
        return;
    }

    file.seekg(dos_header.e_lfanew);

    PE_SIGNATURE pe_signature;
    file.read(reinterpret_cast<char*>(&pe_signature), sizeof(PE_SIGNATURE));

    if (pe_signature.Signature != 0x00004550) { // 'PE\0\0' in little-endian
        std::cerr << "Неверный формат EXE: Отсутствует подпись PE." << std::endl;
        return;
    }

    IMAGE_FILE_HEADER file_header;
    file.read(reinterpret_cast<char*>(&file_header), sizeof(IMAGE_FILE_HEADER));

    std::cout << "Файл: " << filepath << std::endl;
    std::cout << "Количество секций: " << file_header.NumberOfSections << std::endl;

    std::cout << "\nХарактеристики файла (IMAGE_FILE_HEADER.Characteristics): 0x" << std::hex << file_header.Characteristics << std::dec << std::endl;
    // Interpret some common characteristics flags
    if (file_header.Characteristics & 0x0001) std::cout << "  - IMAGE_FILE_RELOCS_STRIPPED (Relocation information was stripped from the file.)" << std::endl;
    if (file_header.Characteristics & 0x0002) std::cout << "  - IMAGE_FILE_EXECUTABLE_IMAGE (The file is executable (no unresolved external references).)" << std::endl;
    if (file_header.Characteristics & 0x0004) std::cout << "  - IMAGE_FILE_LINE_NUMS_STRIPPED (COFF line numbers were stripped from the file.)" << std::endl;
    if (file_header.Characteristics & 0x0008) std::cout << "  - IMAGE_FILE_LOCAL_SYMS_STRIPPED (COFF symbol table entries for local symbols were stripped from the file.)" << std::endl;
    if (file_header.Characteristics & 0x0010) std::cout << "  - IMAGE_FILE_AGGRESIVE_WS_TRIM (Aggressively trim working set.)" << std::endl;
    if (file_header.Characteristics & 0x0020) std::cout << "  - IMAGE_FILE_LARGE_ADDRESS_AWARE (The application can handle addresses larger than 2 GB.)" << std::endl;
    if (file_header.Characteristics & 0x0080) std::cout << "  - IMAGE_FILE_BYTES_REVERSED_LO (Little endian on 32-bit word machine.)" << std::endl;
    if (file_header.Characteristics & 0x0100) std::cout << "  - IMAGE_FILE_32BIT_MACHINE (The computer supports 32-bit words.)" << std::endl;
    if (file_header.Characteristics & 0x0200) std::cout << "  - IMAGE_FILE_DEBUG_STRIPPED (Debugging information was removed and stored separately in a .pdb file.)" << std::endl;
    if (file_header.Characteristics & 0x0400) std::cout << "  - IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP (If the image is on removable media, copy it to and run it from the swap file.)" << std::endl;
    if (file_header.Characteristics & 0x0800) std::cout << "  - IMAGE_FILE_NET_RUN_FROM_SWAP (If the image is on network media, copy it to and run it from the swap file.)" << std::endl;
    if (file_header.Characteristics & 0x1000) std::cout << "  - IMAGE_FILE_SYSTEM (The image is a system file.)" << std::endl;
    if (file_header.Characteristics & 0x2000) std::cout << "  - IMAGE_FILE_DLL (The image is a dynamic-link library (DLL).)" << std::endl;
    if (file_header.Characteristics & 0x4000) std::cout << "  - IMAGE_FILE_UP_SYSTEM_ONLY (The image should be run only on a uniprocessor computer.)" << std::endl;
    if (file_header.Characteristics & 0x8000) std::cout << "  - IMAGE_FILE_BYTES_REVERSED_HI (Big endian on 32-bit word machine.)" << std::endl;

    // Read Optional Header
    if (file_header.SizeOfOptionalHeader > 0) {
        IMAGE_OPTIONAL_HEADER32 optional_header;
        file.read(reinterpret_cast<char*>(&optional_header), sizeof(IMAGE_OPTIONAL_HEADER32));

        std::cout << "\nOptional Header:" << std::endl;
        std::cout << "  Адрес точки входа: 0x" << std::hex << optional_header.AddressOfEntryPoint << std::dec << std::endl;
        std::cout << "  Базовый адрес образа: 0x" << std::hex << optional_header.ImageBase << std::dec << std::endl;

        std::cout << "\nКаталоги данных (Data Directories):" << std::endl;
        const char* data_dir_names[] = {
            "Export Table", "Import Table", "Resource Table", "Exception Table",
            "Certificate Table", "Base Relocation Table", "Debug", "Architecture",
            "Global Ptr", "TLS Table", "Load Config Table", "Bound Import",
            "IAT", "Delay Import Descriptor", "COM+ Runtime Header", "Reserved"
        };

        for (int i = 0; i < optional_header.NumberOfRvaAndSizes; ++i) {
            std::cout << "  " << data_dir_names[i] << ": Виртуальный адрес = 0x" << std::hex << optional_header.DataDirectory[i].VirtualAddress
                      << ", Размер = 0x" << optional_header.DataDirectory[i].Size << std::dec << std::endl;
        }
    }

    std::cout << "\nСекции:" << std::endl;
    for (int i = 0; i < file_header.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER section_header;
        file.read(reinterpret_cast<char*>(&section_header), sizeof(IMAGE_SECTION_HEADER));

        std::cout << "  Имя: " << std::string(section_header.Name, 8) << std::endl;
        std::cout << "    Виртуальный размер: " << section_header.VirtualSize << std::endl;
        std::cout << "    Виртуальный адрес: " << std::hex << "0x" << section_header.VirtualAddress << std::dec << std::endl;
        std::cout << "    Размер сырых данных: " << section_header.SizeOfRawData << std::endl;
        std::cout << "    Указатель на сырые данные: " << std::hex << "0x" << section_header.PointerToRawData << std::dec << std::endl;

        // If this is the code section, attempt to disassemble it
        std::string section_name_str(section_header.Name, 8);
        if (section_name_str.find(".text") != std::string::npos || section_name_str.find("CODE") != std::string::npos) {
            std::cout << "\nДизассемблирование секции '" << section_name_str << "':" << std::endl;

            // Read the raw code bytes
            std::vector<uint8_t> code_bytes(section_header.SizeOfRawData);
            file.seekg(section_header.PointerToRawData);
            file.read(reinterpret_cast<char*>(code_bytes.data()), section_header.SizeOfRawData);

            // Disassemble the code
            disassemble_x86(code_bytes, section_header.VirtualAddress);
        }
    }

    file.close();
}