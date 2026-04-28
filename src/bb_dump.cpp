/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
 */

#include "bb_dump.h"
#include "bb_process.h"
#include "bb_memory_accessor.h"
#include "bb_log_sink.h"

#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>

namespace bytebinder {
    namespace {
        bool is_anonymous_mapping(const region_info& region) {
            return region.mapped_path.empty();
        }

        bool is_special_mapping(const region_info& region) {
            return !region.mapped_path.empty() && region.mapped_path[0] == '[';
        }

        std::string format_address_filename(uintptr_t address) {
            std::ostringstream stream;
            stream << "region_0x" << std::hex << std::setw(16) << std::setfill('0') << address << ".bin";
            return stream.str();
        }

        std::string protection_to_string(int posix_protection) {
            std::string result;
            result += (posix_protection & protection::read)    ? 'r' : '-';
            result += (posix_protection & protection::write)   ? 'w' : '-';
            result += (posix_protection & protection::execute) ? 'x' : '-';
            return result;
        }

        std::string json_escape(std::string_view value) {
            std::string out;
            out.reserve(value.size() + 2);
            for (char character : value) {
                switch (character) {
                    case '"':  out += "\\\""; break;
                    case '\\': out += "\\\\"; break;
                    case '\n': out += "\\n"; break;
                    case '\r': out += "\\r"; break;
                    case '\t': out += "\\t"; break;
                    default:   out += character; break;
                }
            }
            return out;
        }
    }

    memory_dump_result dump_memory_for_process(
        const process& target_process,
        std::filesystem::path output_directory,
        const memory_dump_options& options) {
        memory_dump_result aggregate;
        memory_accessor& bound_accessor = target_process.accessor();

        std::error_code dir_error;
        std::filesystem::create_directories(output_directory, dir_error);
        if (dir_error) {
            log(log_level::error,
                "dump_memory: could not create output directory: " + dir_error.message());
            return aggregate;
        }

        struct manifest_entry {
            uintptr_t base;
            size_t size_in_memory;
            size_t bytes_written;
            int protection_bits;
            std::string mapped_path;
            std::string file_name;
        };
        std::vector<manifest_entry> entries;

        constexpr size_t copy_chunk = 1024 * 1024;
        std::vector<uint8_t> chunk_buffer(copy_chunk);

        for (auto& region : bound_accessor.regions()) {
            if ((region.protection & protection::read) == 0) {
                ++aggregate.regions_skipped;
                continue;
            }
            const bool is_executable = (region.protection & protection::execute) != 0;
            const bool is_writable   = (region.protection & protection::write)   != 0;
            const bool is_readonly   = !is_executable && !is_writable;

            if (is_executable && !options.include_executable) { ++aggregate.regions_skipped; continue; }
            if (is_writable   && !is_executable && !options.include_writable_data) { ++aggregate.regions_skipped; continue; }
            if (is_readonly && !options.include_readonly_data) { ++aggregate.regions_skipped; continue; }
            if (is_anonymous_mapping(region) && !options.include_anonymous_mappings) {
                ++aggregate.regions_skipped; continue;
            }
            if (is_special_mapping(region) && !options.include_special_mappings) {
                ++aggregate.regions_skipped; continue;
            }
            if (options.min_region_size != 0 && region.size < options.min_region_size) {
                ++aggregate.regions_skipped; continue;
            }
            if (options.max_region_size != 0 && region.size > options.max_region_size) {
                ++aggregate.regions_skipped; continue;
            }

            const std::string file_name = format_address_filename(region.base);
            const std::filesystem::path file_path = output_directory / file_name;
            std::ofstream output(file_path, std::ios::binary);
            if (!output) {
                log(log_level::warn,
                    "dump_memory: could not open " + file_path.string());
                ++aggregate.regions_skipped;
                continue;
            }

            size_t bytes_written = 0;
            for (size_t offset = 0; offset < region.size; offset += copy_chunk) {
                const size_t want = std::min<size_t>(copy_chunk, region.size - offset);
                const size_t got = bound_accessor.read(region.base + offset,
                                                          chunk_buffer.data(), want);
                if (got == 0) {
                    log(log_level::warn,
                        "dump_memory: short read at region 0x" + std::to_string(region.base));
                    break;
                }
                output.write(reinterpret_cast<const char*>(chunk_buffer.data()),
                              static_cast<std::streamsize>(got));
                bytes_written += got;
                if (got < want) break;
            }
            output.close();

            manifest_entry entry;
            entry.base = region.base;
            entry.size_in_memory = region.size;
            entry.bytes_written = bytes_written;
            entry.protection_bits = region.protection;
            entry.mapped_path = region.mapped_path;
            entry.file_name = file_name;
            entries.push_back(std::move(entry));

            ++aggregate.regions_dumped;
            aggregate.total_bytes_written += bytes_written;
        }

        const std::filesystem::path manifest_path = output_directory / "manifest.json";
        std::ofstream manifest_stream(manifest_path);
        manifest_stream << "{\n  \"regions\": [\n";
        for (size_t entry_index = 0; entry_index < entries.size(); ++entry_index) {
            const auto& entry = entries[entry_index];
            manifest_stream << "    {\n";
            manifest_stream << "      \"base\": \"0x" << std::hex << entry.base << "\",\n" << std::dec;
            manifest_stream << "      \"size_in_memory\": " << entry.size_in_memory << ",\n";
            manifest_stream << "      \"bytes_written\": " << entry.bytes_written << ",\n";
            manifest_stream << "      \"protection\": \"" << protection_to_string(entry.protection_bits) << "\",\n";
            manifest_stream << "      \"mapped_path\": \"" << json_escape(entry.mapped_path) << "\",\n";
            manifest_stream << "      \"file\": \"" << entry.file_name << "\"\n";
            manifest_stream << "    }" << (entry_index + 1 < entries.size() ? "," : "") << "\n";
        }
        manifest_stream << "  ]\n}\n";
        aggregate.manifest_path = manifest_path;

        return aggregate;
    }
}
