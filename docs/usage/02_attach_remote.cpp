// docs/usage/02_attach_remote.cpp
//
// Attaches to another process by PID and runs an IDA-style scan against one
// of its modules. Shows the cross-process API surface — `bb::process::attach`
// returns the same `bb::process` type that `bb::process::current()` returns,
// so the rest of the API is identical.
//
// On Linux, requires that the calling user can `process_vm_readv` the target
// (typically: same UID OR CAP_SYS_PTRACE).

#include <bytebinder.h>
#include <cstdio>
#include <cstdlib>

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr, "usage: %s <pid> <ida_pattern>\n", argv[0]);
        return 1;
    }
    auto target = bb::process::attach(static_cast<uint32_t>(std::atoi(argv[1])));
    auto first = target.scan(argv[2]);
    if (first.valid()) {
        std::printf("first match at 0x%lx\n", first.address);
    } else {
        std::printf("no match\n");
    }
    auto all = target.scan_all(argv[2]);
    std::printf("total matches: %zu\n", all.matches.size());
    return 0;
}
