#include <catch2/catch_test_macros.hpp>
#include "bytebinder.h"
#include "test_support.h"

// dump_memory copies in 1 MiB chunks, which crosses ASan global redzones in
// the test binary's data segments.
#if !BYTEBINDER_HAS_ASAN

TEST_CASE("process::dump_memory writes regions and a manifest", "[process][dump]") {
    namespace fs = std::filesystem;
    fs::path tmp_dir = fs::temp_directory_path() / "bytebinder_dump_test";
    fs::remove_all(tmp_dir);

    auto current_process = bb::process::current();
    bb::memory_dump_options options;
    options.include_executable = true;
    options.include_writable_data = true;
    options.include_readonly_data = true;
    // Windows VirtualQueryEx never populates a mapped path, so every region
    // looks "anonymous". Including anonymous mappings makes the test portable
    // across Linux (which uses the flag to skip [heap]/[stack]) and Windows
    // (where it's the only way regions get dumped at all).
    options.include_anonymous_mappings = true;
    options.min_region_size = 4096;
    // Windows VirtualQueryEx returns whole DLL images as single regions,
    // which can be tens of MiB. Cap generously so something gets dumped on
    // every platform.
    options.max_region_size = 16 * 1024 * 1024;

    auto result = current_process.dump_memory(tmp_dir, options);

    REQUIRE(result.regions_dumped > 0);
    REQUIRE(fs::exists(result.manifest_path));
    REQUIRE(fs::file_size(result.manifest_path) > 0);

    fs::remove_all(tmp_dir);
}

#endif // !BYTEBINDER_HAS_ASAN
