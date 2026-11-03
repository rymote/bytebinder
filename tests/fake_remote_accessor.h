#pragma once

#include "bytebinder.h"

// Accessor that claims to be remote and fails every operation; lets tests
// exercise the local-only guards in bb::mem without spawning a process.
struct fake_remote_accessor : bb::memory_accessor {
    bool is_local() const noexcept override { return false; }
    std::optional<uint32_t> process_id() const noexcept override { return 12345; }
    size_t read(uintptr_t, void*, size_t) override { return 0; }
    size_t write(uintptr_t, const void*, size_t) override { return 0; }
    int read_protection(uintptr_t) override { return 0; }
    int set_protection(uintptr_t, size_t, int) override { return 0; }
    std::vector<bb::region_info> regions() override { return {}; }
    std::vector<bb::module_info> modules() override { return {}; }
};
