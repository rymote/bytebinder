// docs/usage/03_progressive_value_search.cpp
//
// Demonstrates how an APP composes the CheatEngine-style "first scan, next
// scan" workflow on top of bytebinder's stateless scanning primitives. The
// library does not maintain scan state; the app keeps the result vector and
// filters it on each subsequent pass.
//
// Workflow:
//   1) initial scan_value finds every address holding the value the user
//      currently observes (e.g. their HP at full).
//   2) the user changes the value (takes damage); the app reads each
//      previous candidate and keeps only those that match the new value.
//   3) repeat until the candidate set narrows to a single address.

#include <bytebinder.h>
#include <cstdio>
#include <cstdlib>
#include <vector>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <pid>\n", argv[0]);
        return 1;
    }
    auto target = bb::process::attach(static_cast<uint32_t>(std::atoi(argv[1])));

    auto pass1 = target.scan_value<int32_t>(100);
    std::vector<uintptr_t> candidates = pass1.matches;
    std::printf("pass 1: %zu candidates\n", candidates.size());

    int32_t new_value = 95;
    std::vector<uintptr_t> remaining;
    for (uintptr_t address : candidates) {
        int32_t observed = target.at(address).read<int32_t>();
        if (observed == new_value) remaining.push_back(address);
    }
    std::printf("pass 2: %zu candidates\n", remaining.size());

    return 0;
}
