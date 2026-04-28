/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
 */

#include "pattern.h"
#include "log_sink.h"
#include "mem.h"
#include "memory_accessor.h"

#include <algorithm>

namespace bytebinder {
    pattern::pattern(std::string signature_bytes, std::string match_mask)
        : signature(std::move(signature_bytes)), mask(std::move(match_mask)) {}

    bool pattern::match_local(uintptr_t haystack_address) const noexcept {
        const auto* haystack = reinterpret_cast<const unsigned char*>(haystack_address);
        return match_buffer(haystack);
    }

    bool pattern::match_buffer(const uint8_t* buffer) const noexcept {
        const size_t pattern_size = size();
        for (size_t index = 0; index < pattern_size; ++index) {
            if (mask[index] == '?') continue;
            if (buffer[index] != static_cast<unsigned char>(signature[index])) return false;
        }
        return true;
    }

    uintptr_t pattern::scan() const {
        const size_t pattern_size = size();
        if (pattern_size == 0 || mem::storage.size < pattern_size) {
            return std::numeric_limits<uintptr_t>::max();
        }
        const size_t last_offset = mem::storage.size - pattern_size;
        for (size_t offset = 0; offset <= last_offset; ++offset) {
            if (match_local(mem::storage.base + offset)) {
                return mem::storage.base + offset;
            }
        }
        return std::numeric_limits<uintptr_t>::max();
    }

    uintptr_t pattern::scan(memory_accessor& accessor_ref,
                             uintptr_t base, size_t total_size) const {
        const size_t pattern_size = size();
        if (pattern_size == 0 || total_size < pattern_size) {
            return std::numeric_limits<uintptr_t>::max();
        }

        constexpr size_t window_step = 64 * 1024;
        const size_t window_capacity = window_step + pattern_size;
        std::vector<uint8_t> window_buffer(window_capacity);

        uintptr_t window_start = base;
        const uintptr_t scan_end = base + total_size;

        while (window_start + pattern_size <= scan_end) {
            const size_t want_bytes = std::min<size_t>(window_capacity,
                                                        scan_end - window_start);
            const size_t got_bytes = accessor_ref.read(window_start,
                                                        window_buffer.data(),
                                                        want_bytes);
            if (got_bytes >= pattern_size) {
                const size_t last_match_offset = got_bytes - pattern_size;
                for (size_t offset = 0; offset <= last_match_offset; ++offset) {
                    if (match_buffer(window_buffer.data() + offset)) {
                        return window_start + offset;
                    }
                }
            }
            if (got_bytes < want_bytes) {
                log(log_level::debug,
                    "pattern::scan: short read, advancing window");
                window_start += window_step;
                continue;
            }
            window_start += window_step;
        }

        return std::numeric_limits<uintptr_t>::max();
    }

    size_t pattern::scan_all(memory_accessor& target_accessor,
                              uintptr_t base, size_t total_size,
                              size_t max_results,
                              const std::function<bool(uintptr_t)>& on_match) const {
        const size_t pattern_size = size();
        if (pattern_size == 0 || total_size < pattern_size) return 0;

        constexpr size_t window_step = 64 * 1024;
        const size_t window_capacity = window_step + pattern_size;
        std::vector<uint8_t> window_buffer(window_capacity);

        uintptr_t window_start = base;
        const uintptr_t scan_end = base + total_size;
        size_t matches_reported = 0;

        while (window_start + pattern_size <= scan_end) {
            const size_t want_bytes = std::min<size_t>(window_capacity,
                                                        scan_end - window_start);
            const size_t got_bytes = target_accessor.read(window_start,
                                                           window_buffer.data(),
                                                           want_bytes);
            if (got_bytes >= pattern_size) {
                const size_t inclusive_last_match_offset = got_bytes - pattern_size;
                // Avoid double-reporting a match that lies exactly on the
                // boundary between two consecutive windows. The match at
                // `offset == window_step` in the current window has the same
                // address as `offset == 0` in the next window, so only the
                // final window scans through to `inclusive_last_match_offset`.
                const bool is_final_window = want_bytes < window_capacity;
                const size_t exclusive_upper_bound = is_final_window
                    ? inclusive_last_match_offset + 1
                    : std::min<size_t>(inclusive_last_match_offset + 1, window_step);
                for (size_t offset = 0; offset < exclusive_upper_bound; ++offset) {
                    if (!match_buffer(window_buffer.data() + offset)) continue;
                    ++matches_reported;
                    if (!on_match(window_start + offset)) return matches_reported;
                    if (max_results != 0 && matches_reported >= max_results) {
                        return matches_reported;
                    }
                }
            }
            window_start += window_step;
        }
        return matches_reported;
    }

    size_t pattern::scan_all(memory_accessor& target_accessor,
                              uintptr_t base, size_t total_size,
                              size_t max_results,
                              const std::function<bool(uintptr_t)>& on_match,
                              const std::atomic<bool>* cancel,
                              const std::function<void(const scan_progress&)>& on_progress) const {
        const size_t pattern_size = size();
        if (pattern_size == 0 || total_size < pattern_size) return 0;

        constexpr size_t window_step = 64 * 1024;
        const size_t window_capacity = window_step + pattern_size;
        std::vector<uint8_t> window_buffer(window_capacity);

        uintptr_t window_start = base;
        const uintptr_t scan_end = base + total_size;
        size_t matches_reported = 0;

        while (window_start + pattern_size <= scan_end) {
            if (cancel && cancel->load(std::memory_order_relaxed)) break;
            const size_t want_bytes = std::min<size_t>(window_capacity,
                                                        scan_end - window_start);
            const size_t got_bytes = target_accessor.read(window_start,
                                                            window_buffer.data(),
                                                            want_bytes);
            if (got_bytes >= pattern_size) {
                const size_t inclusive_last_match_offset = got_bytes - pattern_size;
                const bool is_final_window = want_bytes < window_capacity;
                const size_t exclusive_upper_bound = is_final_window
                    ? inclusive_last_match_offset + 1
                    : std::min<size_t>(inclusive_last_match_offset + 1, window_step);
                for (size_t offset = 0; offset < exclusive_upper_bound; ++offset) {
                    if (!match_buffer(window_buffer.data() + offset)) continue;
                    ++matches_reported;
                    if (!on_match(window_start + offset)) return matches_reported;
                    if (max_results != 0 && matches_reported >= max_results) {
                        return matches_reported;
                    }
                }
            }
            window_start += window_step;
            if (on_progress) {
                scan_progress progress;
                const uintptr_t advanced = window_start - base;
                progress.bytes_scanned = advanced > total_size ? total_size : advanced;
                progress.bytes_total   = total_size;
                progress.matches_so_far = matches_reported;
                on_progress(progress);
            }
        }
        return matches_reported;
    }

    pattern parse_ida_pattern(std::string_view ida_pattern) {
        std::string signature_bytes;
        std::string match_mask;
        signature_bytes.reserve(ida_pattern.size() / 2);
        match_mask.reserve(ida_pattern.size() / 2);

        auto is_hex_digit = [](char character) {
            return (character >= '0' && character <= '9')
                || (character >= 'a' && character <= 'f')
                || (character >= 'A' && character <= 'F');
        };
        auto hex_value = [](char character) -> int {
            if (character >= '0' && character <= '9') return character - '0';
            if (character >= 'a' && character <= 'f') return character - 'a' + 10;
            if (character >= 'A' && character <= 'F') return character - 'A' + 10;
            return 0;
        };

        for (size_t cursor = 0; cursor < ida_pattern.size(); ) {
            const char current = ida_pattern[cursor];
            if (current == '\0') break;
            if (current == ' ' || current == '\t') { ++cursor; continue; }
            if (current == '?') {
                signature_bytes.push_back('\x00');
                match_mask.push_back('?');
                ++cursor;
                if (cursor < ida_pattern.size() && ida_pattern[cursor] == '?') {
                    ++cursor;
                }
                continue;
            }
            if (is_hex_digit(current)) {
                if (cursor + 1 >= ida_pattern.size()
                    || ida_pattern[cursor + 1] == '\0') {
                    throw memory_operation_exception("Incomplete byte in pattern.",
                        memory_error_code::PATTERN_MATCH_FAILED);
                }
                const char second = ida_pattern[cursor + 1];
                if (!is_hex_digit(second)) {
                    throw memory_operation_exception("Invalid hex digit in pattern.",
                        memory_error_code::PATTERN_MATCH_FAILED);
                }
                signature_bytes.push_back(
                    static_cast<char>((hex_value(current) << 4) | hex_value(second)));
                match_mask.push_back('x');
                cursor += 2;
                continue;
            }
            throw memory_operation_exception("Unexpected character in pattern.",
                memory_error_code::PATTERN_MATCH_FAILED);
        }

        if (signature_bytes.empty()) {
            throw memory_operation_exception("Pattern is empty.",
                memory_error_code::PATTERN_MATCH_FAILED);
        }
        return pattern(std::move(signature_bytes), std::move(match_mask));
    }
}
