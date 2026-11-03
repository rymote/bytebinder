#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <limits>

#if !defined(_WIN32)
    #include <sys/wait.h>
    #include <sys/types.h>
    #include <signal.h>
    #include <unistd.h>
#else
    #include <windows.h>
#endif

// Detect AddressSanitizer in a compiler-portable way. MSVC's preprocessor
// errors on `__has_feature(address_sanitizer)` even when guarded by
// `defined(__has_feature) &&` because undefined identifiers in #if
// expressions become 0, producing the syntax `0(address_sanitizer)`.
// Splitting the check into nested #if/#elif keeps the function-like macro
// invocation out of any code path MSVC will see.
#if defined(__SANITIZE_ADDRESS__)
#  define BYTEBINDER_HAS_ASAN 1
#elif defined(__has_feature)
#  if __has_feature(address_sanitizer)
#    define BYTEBINDER_HAS_ASAN 1
#  else
#    define BYTEBINDER_HAS_ASAN 0
#  endif
#else
#  define BYTEBINDER_HAS_ASAN 0
#endif

extern uint8_t buffer[1024];

// Defined in test_support.cpp, a separate translation unit from every caller,
// so the optimizer can never inline or fold calls to it: find_xrefs needs a
// real `call` instruction to detect.
extern volatile int bytebinder_test_marker_observable;
extern "C" void bytebinder_test_marker_function();
