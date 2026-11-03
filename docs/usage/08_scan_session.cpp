// docs/usage/08_scan_session.cpp
//
// A Cheat Engine-style progressive value search in this process: find an exact
// value, then narrow the survivors across mutations with next-scan predicates
// (decreased, equals, ...), with a single level of undo. The same session drives
// a remote target: swap bb::process::current() for bb::process::attach(pid).

#include <bytebinder.h>

#include <cinttypes>
#include <cstdint>
#include <cstdio>

namespace {
    volatile int32_t health = 100;
}

int main() {
    auto current = bb::process::current();
    bb::scan_session session(current, bb::scan_value_type::int32);

    // First scan: every int32 that currently equals 100. `health` is one hit
    // among however many the address space happens to hold.
    session.first_scan(bb::scan_constraint::equals<int32_t>(100));
    std::printf("after first scan: %zu candidate(s)\n", session.result_count());

    // The value drops. Keep only addresses that went down, then pin to 80.
    health = 80;
    session.next_scan(bb::scan_constraint::decreased());
    session.next_scan(bb::scan_constraint::equals<int32_t>(80));
    std::printf("after narrowing: %zu candidate(s)\n", session.result_count());

    for (const auto& match : session.results()) {
        std::printf("  candidate at 0x%" PRIxPTR "\n", match.address);
    }

    // One level of undo restores the survivor set from before the last next_scan.
    session.undo();
    std::printf("after undo: %zu candidate(s)\n", session.result_count());

    return 0;
}
