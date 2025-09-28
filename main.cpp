#include <iostream>
#include <string>
#include "pe_parser.h"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Использование: " << argv[0] << " <путь_к_exe_файлу>" << std::endl;
        return 1;
    }

    read_exe_header(argv[1]);

    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Использование: " << argv[0] << " <путь_к_exe_файлу>" << std::endl;
        return 1;
    }

    read_exe_header(argv[1]);

    return 0;
}