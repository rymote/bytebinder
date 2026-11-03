#include <catch2/catch_test_macros.hpp>
#include "bytebinder.h"
#include "test_support.h"

TEST_CASE("set_log_sink captures error from missing module", "[log_sink]") {
    std::vector<std::pair<bb::log_level, std::string>> captured;
    bb::set_log_sink([&](bb::log_level level, std::string_view message) {
        captured.emplace_back(level, std::string(message));
    });
    auto current_process = bb::process::current();
    REQUIRE_THROWS_AS(current_process.scan("DE AD", "definitely-not-a-real-module-xyz"),
                       bb::memory_operation_exception);
    bb::set_log_sink({}); // clear

    bool saw_module_error = false;
    for (const auto& [level, message] : captured) {
        if (level == bb::log_level::error
            && message.find("module not found") != std::string::npos) {
            saw_module_error = true;
            break;
        }
    }
    REQUIRE(saw_module_error);
}
