/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_watchpoint.h"

#include <cstdint>
#include <optional>

namespace bytebinder {
    /**
     * @brief Pure encoding of the x86/x86_64 debug control register (DR7) for a
     *        single hardware watchpoint slot. This holds no OS state and touches
     *        no registers; it is the bit layout the per-platform debugger code
     *        feeds into GetThreadContext, ptrace PTRACE_POKEUSER, or the Mach
     *        x86_DEBUG_STATE64, so it can be verified on its own.
     *
     * DR7 layout used here:
     *  - bit 2*slot        local enable for the slot (Ln).
     *  - bits 16+4*slot..  a four-bit field per slot: the low two bits are the
     *                      read/write condition, the high two bits are the length.
     * Read/write encoding: execute = 0b00, write = 0b01, read_write = 0b11.
     * Length encoding: 1 byte = 0b00, 2 bytes = 0b01, 8 bytes = 0b10, 4 bytes = 0b11.
     */
    struct debug_register_encoding {
        /// @brief Number of hardware debug address slots (DR0..DR3).
        static constexpr int slot_count = 4;

        /// @brief True if @p slot names a valid debug slot.
        [[nodiscard]] static constexpr bool is_valid_slot(int slot) noexcept {
            return slot >= 0 && slot < slot_count;
        }

        /// @brief The DR7 local-enable bit for @p slot.
        [[nodiscard]] static constexpr uint64_t enable_bit(int slot) noexcept {
            return uint64_t{1} << (2 * slot);
        }

        /// @brief The DR7 bits owned by @p slot: its enable bits (local and
        ///        global) and its four-bit condition/length field. These are the
        ///        bits to clear before writing a new configuration or disabling.
        [[nodiscard]] static constexpr uint64_t slot_mask(int slot) noexcept {
            return (uint64_t{0b11} << (2 * slot)) | (uint64_t{0b1111} << (16 + 4 * slot));
        }

        /// @brief The two-bit read/write condition field for @p condition.
        [[nodiscard]] static constexpr uint64_t condition_bits(watchpoint_condition condition) noexcept {
            switch (condition) {
                case watchpoint_condition::execute:    return 0b00;
                case watchpoint_condition::write:      return 0b01;
                case watchpoint_condition::read_write: return 0b11;
            }
            return 0b01;
        }

        /// @brief The two-bit length field for a data watchpoint of @p size bytes,
        ///        or nullopt if @p size is not 1, 2, 4, or 8.
        [[nodiscard]] static constexpr std::optional<uint64_t> length_bits(size_t size) noexcept {
            switch (size) {
                case 1: return uint64_t{0b00};
                case 2: return uint64_t{0b01};
                case 8: return uint64_t{0b10};
                case 4: return uint64_t{0b11};
                default: return std::nullopt;
            }
        }

        /**
         * @brief Produces the DR7 value that configures @p slot for @p point,
         *        starting from @p current_control and leaving every other slot's
         *        bits untouched. Returns nullopt if @p slot is out of range or the
         *        data size is unsupported. For the execute condition the length is
         *        forced to one byte and size is ignored.
         */
        [[nodiscard]] static std::optional<uint64_t> apply_to_control(
                uint64_t current_control, int slot, const watchpoint& point) noexcept {
            if (!is_valid_slot(slot)) {
                return std::nullopt;
            }

            uint64_t length;
            if (point.condition == watchpoint_condition::execute) {
                length = 0b00;
            } else {
                const std::optional<uint64_t> encoded_length = length_bits(point.size);
                if (!encoded_length.has_value()) {
                    return std::nullopt;
                }
                length = *encoded_length;
            }

            const uint64_t field = condition_bits(point.condition) | (length << 2);
            uint64_t control = current_control & ~slot_mask(slot);
            control |= enable_bit(slot);
            control |= field << (16 + 4 * slot);
            return control;
        }

        /// @brief Produces the DR7 value with @p slot disabled, leaving every
        ///        other slot's bits untouched.
        [[nodiscard]] static constexpr uint64_t clear_in_control(uint64_t current_control, int slot) noexcept {
            if (!is_valid_slot(slot)) {
                return current_control;
            }
            return current_control & ~slot_mask(slot);
        }

        /// @brief The slot whose breakpoint the debug status register (DR6)
        ///        reports as triggered, read from its low four bits (B0..B3), or
        ///        -1 if none is set. When several fire at once the lowest wins.
        [[nodiscard]] static constexpr int triggered_slot(uint64_t debug_status) noexcept {
            for (int slot = 0; slot < slot_count; ++slot) {
                if (debug_status & (uint64_t{1} << slot)) {
                    return slot;
                }
            }
            return -1;
        }
    };
}
