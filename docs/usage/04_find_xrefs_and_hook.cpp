// docs/usage/04_find_xrefs_and_hook.cpp
//
// Finds every callsite of a target function and patches each one with a
// detour. This is the v0.3 idiom for "rewrite all callers" — much cleaner
// than scanning for bytes that look like a CALL instruction.

#include <bytebinder.h>
#include <cstdio>

extern "C" void target_function() { std::printf("original\n"); }
extern "C" void detour_function() { std::printf("detour\n"); }

int main() {
    auto current = bb::process::current();
    auto xrefs = current.find_xrefs(reinterpret_cast<uintptr_t>(&target_function));
    for (const auto& reference : xrefs) {
        if (reference.kind == bb::xref_kind::call) {
            bb::mem callsite(reinterpret_cast<void*>(reference.instruction_address));
            callsite.set_call(reinterpret_cast<void*>(&detour_function));
        }
    }
    target_function();
    return 0;
}
