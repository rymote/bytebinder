#pragma once

#include <cstdint>

struct chain_test_leaf {
    uint32_t value;
    uint8_t  padding[60];
};
