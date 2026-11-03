#pragma once

#include "bytebinder.h"

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

// In-memory accessor backing a single writable region, so scan-session tests
// run against a small deterministic buffer instead of the whole process.
struct scan_test_accessor : bb::memory_accessor {
    uintptr_t base;
    std::vector<uint8_t> storage;
    bool has_module = false;
    bb::module_info module;

    scan_test_accessor(uintptr_t base, size_t size) : base(base), storage(size, 0) {}

    // Marks [base + offset, base + offset + size) as a loaded module, so the
    // pointer scanner treats slots there as static bases.
    void set_module(const std::string& name, size_t offset, size_t size) {
        has_module = true;
        module.name = name;
        module.path = name;
        module.base = base + offset;
        module.size = size;
    }

    bool in_range(uintptr_t address, size_t size) const {
        return address >= base && address + size <= base + storage.size();
    }

    bool is_local() const noexcept override { return false; }
    std::optional<uint32_t> process_id() const noexcept override { return 4321; }

    size_t read(uintptr_t address, void* destination, size_t size) override {
        if (address < base || address >= base + storage.size()) return 0;
        const size_t available = (base + storage.size()) - address;
        const size_t to_copy = std::min(size, available);
        std::memcpy(destination, storage.data() + (address - base), to_copy);
        return to_copy;
    }

    size_t write(uintptr_t address, const void* source, size_t size) override {
        if (!in_range(address, size)) return 0;
        std::memcpy(storage.data() + (address - base), source, size);
        return size;
    }

    int read_protection(uintptr_t) override {
        return bb::protection::read | bb::protection::write;
    }
    int set_protection(uintptr_t, size_t, int) override {
        return bb::protection::read | bb::protection::write;
    }

    std::vector<bb::region_info> regions() override {
        bb::region_info region;
        region.base = base;
        region.size = storage.size();
        region.protection = bb::protection::read | bb::protection::write;
        return {region};
    }
    std::vector<bb::module_info> modules() override {
        if (has_module) return {module};
        return {};
    }

    template<typename ValueType>
    void poke(size_t offset, ValueType value) {
        std::memcpy(storage.data() + offset, &value, sizeof(ValueType));
    }
};
