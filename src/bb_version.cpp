/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#include "bb_version.h"

#ifndef BYTEBINDER_VERSION_STRING
#define BYTEBINDER_VERSION_STRING "0.0.0"
#endif

namespace {
    // Bump whenever any exported struct/class layout changes.
    // Revision 1: baseline (mem, process, memory_accessor, region_info,
    //             module_info, symbol_info, symbolize_result, scan_result,
    //             module_section, instruction, pattern, log_sink).
    // Revision 2: v0.3 additions (xref, instruction_pattern_element,
    //             vtable_candidate, string_table_run, memory_dump_options,
    //             memory_dump_result, chain_step, chain_resolution) and the
    //             new process member functions that use them.
    constexpr uint32_t kAbiRevision = 2;
}

extern "C" const char* bytebinder_version(void) {
    return BYTEBINDER_VERSION_STRING;
}

extern "C" uint32_t bytebinder_abi_revision(void) {
    return kAbiRevision;
}
