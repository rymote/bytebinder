#pragma once

#include "scan_test_accessor.h"

#include <initializer_list>

// A single readable, executable region that holds a hand-built module image, so
// function discovery runs against known bytes instead of whatever a compiler emitted.
struct code_image_accessor : scan_test_accessor {
    code_image_accessor(uintptr_t base, size_t size) : scan_test_accessor(base, size) {
        set_module("image.exe", 0, size);
    }

    std::vector<bb::region_info> regions() override {
        bb::region_info region;
        region.base = base;
        region.size = storage.size();
        region.protection = bb::protection::read | bb::protection::execute;
        return {region};
    }

    void poke_bytes(size_t offset, std::initializer_list<uint8_t> bytes) {
        std::copy(bytes.begin(), bytes.end(), storage.begin() + static_cast<std::ptrdiff_t>(offset));
    }

    void poke_relative(size_t instruction_offset, size_t target_offset) {
        poke<int32_t>(instruction_offset + 1, static_cast<int32_t>(target_offset) - static_cast<int32_t>(instruction_offset + 5));
    }

    void fill_padding(size_t offset, size_t size) {
        std::fill_n(storage.begin() + static_cast<std::ptrdiff_t>(offset), size, static_cast<uint8_t>(0xCC));
    }

    // Writes the PE headers down to a PE32+ optional header pointing at an exception directory.
    void poke_pe_headers(uint32_t table_offset, uint32_t table_size, uint16_t machine = 0x8664) {
        poke<uint16_t>(0, 0x5A4D);
        poke<uint32_t>(0x3C, pe_offset);
        poke<uint32_t>(pe_offset, 0x00004550);
        poke<uint16_t>(pe_offset + 4, machine);
        poke<uint16_t>(optional_offset, 0x20B);
        poke<uint32_t>(optional_offset + 108, 16);
        poke<uint32_t>(optional_offset + 112 + 3 * 8, table_offset);
        poke<uint32_t>(optional_offset + 112 + 3 * 8 + 4, table_size);
    }

    void poke_table_entry(size_t table_offset, size_t index, uint32_t begin, uint32_t end, uint32_t unwind) {
        const size_t entry = table_offset + index * 12;
        poke<uint32_t>(entry, begin);
        poke<uint32_t>(entry + 4, end);
        poke<uint32_t>(entry + 8, unwind);
    }

    static constexpr uint32_t pe_offset = 0x80;
    static constexpr uint32_t optional_offset = pe_offset + 24;
};
