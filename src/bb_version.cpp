/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
 */

#include "bb_version.h"

#ifndef BYTEBINDER_VERSION_STRING
#define BYTEBINDER_VERSION_STRING "0.0.0"
#endif

namespace {
    // Bump whenever any exported struct/class layout changes. Revision 1 is
    // the baseline that snapshots the public surface as of this commit:
    // mem, process, memory_accessor, region_info, module_info, symbol_info,
    // symbolize_result, scan_result, module_section, instruction, pattern,
    // log_sink. Future tasks (10, 13) will add more types but the baseline
    // does not need to be re-bumped within this single-commit work cycle.
    constexpr uint32_t kAbiRevision = 1;
}

extern "C" const char* bytebinder_version(void) {
    return BYTEBINDER_VERSION_STRING;
}

extern "C" uint32_t bytebinder_abi_revision(void) {
    return kAbiRevision;
}
