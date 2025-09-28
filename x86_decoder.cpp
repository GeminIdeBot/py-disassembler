#include "x86_decoder.h"

void disassemble_x86(const std::vector<uint8_t>& code_bytes, uint32_t base_rva) {
    uint32_t current_offset = 0;
    while (current_offset < code_bytes.size()) {
        uint32_t current_rva = base_rva + current_offset;
        std::cout << std::hex << std::setw(8) << std::setfill('0') << current_rva << ": ";

        uint8_t opcode = code_bytes[current_offset];
        std::string instruction = "UNKNOWN";
        int instruction_len = 1; // Default instruction length

        // Basic instruction decoding (x86 32-bit)
        if (opcode == 0x90) {
            instruction = "NOP";
        } else if (opcode == 0xC3) {
            instruction = "RET";
        } else if (opcode == 0x55) {
            instruction = "PUSH EBP";
        } else if (opcode == 0x8B && current_offset + 1 < code_bytes.size() && code_bytes[current_offset + 1] == 0xEC) {
            instruction = "MOV EBP,ESP";
            instruction_len = 2;
        } else if (opcode == 0x83 && current_offset + 2 < code_bytes.size() && code_bytes[current_offset + 1] == 0xEC) {
            instruction = "SUB ESP, " + std::to_string(code_bytes[current_offset + 2]);
            instruction_len = 3;
        }
        // Add more instructions here as needed

        std::cout << instruction << std::endl;
        current_offset += instruction_len;
    }
}