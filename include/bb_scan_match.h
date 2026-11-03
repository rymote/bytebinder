/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_api.h"

#include <array>
#include <cstddef>
#include <cstdint>

namespace bytebinder {
    /**
     * @brief One surviving address in a scan session, with the raw bytes of the
     *        value read there on the most recent scan. The recorded bytes are
     *        what next-scan comparisons such as increased or changed compare
     *        against; only the first scan_value_type_width(type) bytes are
     *        meaningful.
     */
    struct BYTEBINDER_API scan_match {
        uintptr_t address = 0;
        std::array<uint8_t, 8> previous_value{};
    };
}
