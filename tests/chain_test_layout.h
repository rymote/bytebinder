#pragma once

#include <cstdint>

struct chain_test_layout {
    uintptr_t pointer_to_node_a;
    uint64_t  padding_a[3];
};
