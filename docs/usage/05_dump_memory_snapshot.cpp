// docs/usage/05_dump_memory_snapshot.cpp
//
// Dumps the readable memory of the calling process to ./mem-dump/ and prints
// the manifest. The manifest is a JSON file listing every region's base,
// size, protection, and the file containing its bytes.

#include <bytebinder.h>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>

int main() {
    bb::memory_dump_options options;
    options.include_executable = true;
    options.include_writable_data = true;
    options.include_readonly_data = true;
    options.include_anonymous_mappings = false;
    auto result = bb::process::current().dump_memory("./mem-dump", options);
    std::printf("regions dumped: %zu, bytes written: %zu\n",
                result.regions_dumped, result.total_bytes_written);
    std::printf("manifest: %s\n", result.manifest_path.string().c_str());
    std::ifstream manifest_in(result.manifest_path);
    std::string manifest_text((std::istreambuf_iterator<char>(manifest_in)),
                                std::istreambuf_iterator<char>());
    std::printf("--- manifest content ---\n%s", manifest_text.c_str());
    return 0;
}
