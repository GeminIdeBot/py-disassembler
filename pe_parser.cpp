#include "pe_parser.h"

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

    // Read Optional Header
    if (file_header.SizeOfOptionalHeader > 0) {
        IMAGE_OPTIONAL_HEADER32 optional_header;
        file.read(reinterpret_cast<char*>(&optional_header), sizeof(IMAGE_OPTIONAL_HEADER32));

        std::cout << "\nOptional Header:" << std::endl;
        std::cout << "  Адрес точки входа: 0x" << std::hex << optional_header.AddressOfEntryPoint << std::dec << std::endl;
        std::cout << "  Базовый адрес образа: 0x" << std::hex << optional_header.ImageBase << std::dec << std::endl;
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
    }

    file.close();
}