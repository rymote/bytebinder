#include <catch2/catch_test_macros.hpp>
#include "bytebinder.h"
#include "test_support.h"
#include "vmt_target.h"

namespace {
    int vmt_test_observed_value = 0;
    int vmt_test_detour(vmt_target* /*self*/, int input) {
        vmt_test_observed_value = input;
        return input * 1000;
    }

    // Defeats gcc/clang -O3 devirtualization of stack-local virtual calls.
    // The wrapper compiles at -O0 (gcc) / `optnone` (clang) and is also
    // marked noinline so the call site can't fold the body in. Devirtualization
    // happens during inlining and IPA, both of which are disabled here.
#if defined(__GNUC__) && !defined(__clang__)
    __attribute__((noinline, noipa, optimize("O0")))
#elif defined(__clang__)
    __attribute__((noinline, optnone))
#elif defined(_MSC_VER)
    __declspec(noinline)
#endif
    int vmt_test_call_compute(vmt_target* target, int value) {
        return target->compute(value);
    }
}

TEST_CASE("vmt::hook redirects a virtual call and unhook restores it", "[vmt][hook]") {
    vmt_target instance;
    REQUIRE(instance.compute(5) == 6);

    bb::vmt vtable_view(reinterpret_cast<uintptr_t>(&instance));
    // Itanium C++ ABI: a virtual destructor consumes two slots (D1 + D0),
    // so the next user-declared virtual sits at index 2. MSVC uses a single
    // slot, putting compute at index 1.
#if defined(_MSC_VER)
    constexpr size_t compute_index = 1;
#else
    constexpr size_t compute_index = 2;
#endif

    const uintptr_t original_pointer = vtable_view.function_at(compute_index);
    REQUIRE(original_pointer != 0);

    auto handle = vtable_view.hook(compute_index, reinterpret_cast<void*>(&vmt_test_detour));
    REQUIRE(handle.installed());
    REQUIRE(vtable_view.function_at(compute_index)
            == reinterpret_cast<uintptr_t>(&vmt_test_detour));

    vmt_test_observed_value = 0;
    const int detoured_result = vmt_test_call_compute(&instance, 7);
    REQUIRE(vmt_test_observed_value == 7);
    REQUIRE(detoured_result == 7000);

    REQUIRE(handle.unhook());
    REQUIRE_FALSE(handle.installed());

    REQUIRE(vmt_test_call_compute(&instance, 9) == 10);
}
