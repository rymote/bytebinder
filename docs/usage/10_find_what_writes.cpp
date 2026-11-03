// docs/usage/10_find_what_writes.cpp
//
// "Find what writes this address" built on the debugger: attach to a target,
// arm a hardware write watchpoint on every thread, run the event loop, and
// report the instruction that performed each store (symbolized when possible).
//
// Platform model:
//  - Windows: the debugger controls the whole process (DebugActiveProcess).
//  - Linux: it ptrace-attaches and the target is left stopped, so it must be
//    kicked off with an initial continue before the first event arrives.
//  - macOS (x86_64): it rides Mach exception ports; the target keeps running.
//
// Usage: 10_find_what_writes <pid> <hex-address>

#include <bytebinder.h>

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

int main(int argc, char** argv) {
    if (argc < 3) {
        std::printf("usage: %s <pid> <hex-address>\n", argv[0]);
        return 1;
    }

    const uint32_t process_id = static_cast<uint32_t>(std::strtoul(argv[1], nullptr, 0));
    const uintptr_t address = static_cast<uintptr_t>(std::strtoull(argv[2], nullptr, 16));

    bb::debugger debug_session(process_id);
    if (!debug_session.attach()) {
        std::printf("could not attach to %u (needs privilege or permission)\n", process_id);
        return 1;
    }

    // Arm a write watchpoint in slot 0 on every current thread, so whichever
    // thread performs the store traps into the event loop.
    const bb::watchpoint point{address, 8, bb::watchpoint_condition::write};
    for (const auto& thread : debug_session.threads()) {
        debug_session.set_watchpoint(thread.thread_id, 0, point);
    }

    auto symbols = bb::process::attach(process_id);

#if defined(__linux__)
    // ptrace leaves the target stopped after attach; start it running.
    bb::debug_event start{};
    start.thread_id = debug_session.process_id();
    debug_session.continue_event(start, true);
#endif

    for (int caught = 0; caught < 5; ) {
        const auto event = debug_session.wait_for_event(5000);
        if (!event.has_value()) break;

        if (event->kind == bb::debug_event_kind::watchpoint_hit) {
            const uint64_t writer = event->registers.instruction_pointer;
            std::printf("write from 0x%" PRIx64, writer);
            if (auto where = symbols.symbolize(static_cast<uintptr_t>(writer))) {
                std::printf(" (%s+%zu)", where->symbol.name.c_str(), where->offset_from_start);
            }
            std::printf("\n");
            ++caught;
        } else if (event->kind == bb::debug_event_kind::process_exited) {
            break;
        }

        debug_session.continue_event(*event, true);
    }

    for (const auto& thread : debug_session.threads()) {
        debug_session.clear_watchpoint(thread.thread_id, 0);
    }
    debug_session.detach();
    return 0;
}
