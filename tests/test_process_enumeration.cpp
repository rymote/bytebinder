#include <catch2/catch_test_macros.hpp>
#include "bytebinder.h"
#include "test_support.h"

#include <algorithm>

namespace {
    uint32_t current_process_id() {
#if defined(_WIN32)
        return static_cast<uint32_t>(GetCurrentProcessId());
#else
        return static_cast<uint32_t>(getpid());
#endif
    }
}

TEST_CASE("list_processes includes the current process", "[process][enumeration]") {
    const auto processes = bb::list_processes();
    REQUIRE_FALSE(processes.empty());

    const uint32_t self = current_process_id();
    const bool found_self = std::any_of(processes.begin(), processes.end(),
                                        [self](const bb::process_entry& entry) {
                                            return entry.process_id == self;
                                        });
    REQUIRE(found_self);

    // At least one entry should carry a non-empty image name.
    const bool any_named = std::any_of(processes.begin(), processes.end(),
                                       [](const bb::process_entry& entry) {
                                           return !entry.name.empty();
                                       });
    REQUIRE(any_named);
}

TEST_CASE("find_processes_by_name is case-insensitive and finds this process", "[process][enumeration]") {
    const uint32_t self = current_process_id();

    std::string own_name;
    for (const auto& entry : bb::list_processes()) {
        if (entry.process_id == self) {
            own_name = entry.name;
            break;
        }
    }
    REQUIRE_FALSE(own_name.empty());

    std::string upper_name = own_name;
    std::transform(upper_name.begin(), upper_name.end(), upper_name.begin(),
                   [](unsigned char character) { return static_cast<char>(std::toupper(character)); });

    const auto matches = bb::find_processes_by_name(upper_name);
    const bool found_self = std::any_of(matches.begin(), matches.end(),
                                        [self](const bb::process_entry& entry) {
                                            return entry.process_id == self;
                                        });
    REQUIRE(found_self);
}
