// docs/usage/06_vtable_discovery.cpp
//
// Walks read-only data regions looking for arrays of pointers that resolve
// to executable addresses — i.e. likely vtables. Prints the first five
// candidates and their entry counts.

#include <bytebinder.h>
#include <cstdio>

int main() {
    auto current = bb::process::current();
    auto candidates = current.find_vtables(std::nullopt, 4, 5);
    for (const auto& candidate : candidates) {
        std::printf("vtable @ 0x%lx (entries=%zu)\n",
                    candidate.address, candidate.entries.size());
    }
    return 0;
}
