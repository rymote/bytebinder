#pragma once

#include <cstdint>

struct chain_test_node {
    uintptr_t pointer_to_node_b;
    uint64_t  padding_b[3];
};
