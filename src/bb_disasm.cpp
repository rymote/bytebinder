/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
 */

#include "bb_disasm.h"
#include "bb_mem.h"
#include "bb_memory_accessor.h"
#include "bb_memory_exceptions.h"

#include <Zydis/Disassembler.h>
#include <Zydis/Mnemonic.h>

namespace bytebinder {
    namespace {
        constexpr ZydisMachineMode preferred_machine_mode() {
            return sizeof(void*) == 8 ? ZYDIS_MACHINE_MODE_LONG_64
                                      : ZYDIS_MACHINE_MODE_LEGACY_32;
        }

        std::optional<instruction> decode_one(uintptr_t runtime_address,
                                                const uint8_t* byte_buffer,
                                                size_t buffer_length) {
            ZydisDisassembledInstruction decoded{};
            const ZyanStatus status = ZydisDisassembleIntel(
                preferred_machine_mode(),
                static_cast<ZyanU64>(runtime_address),
                byte_buffer, buffer_length, &decoded);
            if (!ZYAN_SUCCESS(status)) {
                return std::nullopt;
            }

            instruction result;
            result.address = runtime_address;
            result.length = decoded.info.length;
            result.text = decoded.text;
            const char* mnemonic_string = ZydisMnemonicGetString(decoded.info.mnemonic);
            result.mnemonic = mnemonic_string ? mnemonic_string : "";
            result.bytes.assign(byte_buffer, byte_buffer + decoded.info.length);
            return result;
        }
    }

    std::optional<instruction> mem::disasm_one() const {
        if (!valid()) {
            return std::nullopt;
        }
        constexpr size_t single_instruction_window = 16;
        std::array<uint8_t, single_instruction_window> staging{};
        const size_t bytes_read = accessor->read(address, staging.data(), staging.size());
        if (bytes_read == 0) {
            return std::nullopt;
        }
        return decode_one(address, staging.data(), bytes_read);
    }

    uintptr_t resolve_rip_relative(uintptr_t instruction_address,
                                     size_t instruction_length,
                                     int32_t signed_displacement) {
        return instruction_address
             + instruction_length
             + static_cast<intptr_t>(signed_displacement);
    }

    std::vector<instruction> mem::disasm(size_t max_instructions, size_t max_bytes) const {
        std::vector<instruction> decoded_instructions;
        if (!valid() || max_instructions == 0 || max_bytes == 0) {
            return decoded_instructions;
        }

        std::vector<uint8_t> window(max_bytes);
        const size_t bytes_read = accessor->read(address, window.data(), max_bytes);
        if (bytes_read == 0) {
            return decoded_instructions;
        }

        decoded_instructions.reserve(max_instructions);
        size_t cursor_offset = 0;
        while (decoded_instructions.size() < max_instructions
               && cursor_offset < bytes_read) {
            auto decoded = decode_one(address + cursor_offset,
                                       window.data() + cursor_offset,
                                       bytes_read - cursor_offset);
            if (!decoded.has_value() || decoded->length == 0) {
                break;
            }
            cursor_offset += decoded->length;
            decoded_instructions.push_back(std::move(*decoded));
        }
        return decoded_instructions;
    }
}
