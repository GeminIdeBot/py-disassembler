#ifndef X86_DECODER_H
#define X86_DECODER_H

#include <vector>
#include <string>
#include <cstdint>
#include <iostream>
#include <iomanip>

void disassemble_x86(const std::vector<uint8_t>& code_bytes, uint32_t base_rva);

#endif // X86_DECODER_H