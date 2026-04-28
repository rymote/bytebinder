// docs/usage/01_read_write_local.cpp
//
// Reads and writes a single integer in the calling process. Demonstrates the
// `bb::mem` fluent surface for typed I/O, the difference between `get<T>` (a
// raw pointer, local-only) and `read<T>` (accessor-mediated, works for both
// local and remote targets), and how to bind a `bb::mem` to an arbitrary
// address.
//
// Build (from the project root):
//   cmake -B build -DBYTEBINDER_BUILD_USAGE_EXAMPLES=ON
//   cmake --build build -j --target usage_01_read_write_local

#include <bytebinder.h>
#include <cstdio>

static int counter = 100;

int main() {
    bb::mem at_counter(reinterpret_cast<void*>(&counter));
    int previous = at_counter.read<int>();
    at_counter.write<int>(previous + 1);
    std::printf("counter went %d -> %d\n", previous, counter);
    return 0;
}
