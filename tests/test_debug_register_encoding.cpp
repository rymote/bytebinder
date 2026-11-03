#include <catch2/catch_test_macros.hpp>
#include "bytebinder.h"

TEST_CASE("debug register length encoding maps supported sizes", "[debugger][watchpoint][encoding]") {
    REQUIRE(bb::debug_register_encoding::length_bits(1) == 0b00);
    REQUIRE(bb::debug_register_encoding::length_bits(2) == 0b01);
    REQUIRE(bb::debug_register_encoding::length_bits(8) == 0b10);
    REQUIRE(bb::debug_register_encoding::length_bits(4) == 0b11);

    REQUIRE_FALSE(bb::debug_register_encoding::length_bits(0).has_value());
    REQUIRE_FALSE(bb::debug_register_encoding::length_bits(3).has_value());
    REQUIRE_FALSE(bb::debug_register_encoding::length_bits(16).has_value());
}

TEST_CASE("debug register condition encoding matches the read/write field", "[debugger][watchpoint][encoding]") {
    REQUIRE(bb::debug_register_encoding::condition_bits(bb::watchpoint_condition::execute) == 0b00);
    REQUIRE(bb::debug_register_encoding::condition_bits(bb::watchpoint_condition::write) == 0b01);
    REQUIRE(bb::debug_register_encoding::condition_bits(bb::watchpoint_condition::read_write) == 0b11);
}

TEST_CASE("debug register control encodes a write watchpoint in slot 0", "[debugger][watchpoint][encoding]") {
    const bb::watchpoint point{0x4000, 4, bb::watchpoint_condition::write};
    const auto control = bb::debug_register_encoding::apply_to_control(0, 0, point);
    REQUIRE(control.has_value());

    // enable bit L0 (bit 0) set, and the slot-0 field (bits 16..19) = write(0b01) | len4(0b11) << 2 = 0b1101.
    REQUIRE(*control == (uint64_t{1} | (uint64_t{0b1101} << 16)));
}

TEST_CASE("debug register control encodes a read/write watchpoint in slot 1", "[debugger][watchpoint][encoding]") {
    const bb::watchpoint point{0x8000, 1, bb::watchpoint_condition::read_write};
    const auto control = bb::debug_register_encoding::apply_to_control(0, 1, point);
    REQUIRE(control.has_value());

    // enable bit L1 (bit 2) set, and the slot-1 field (bits 20..23) = read_write(0b11) | len1(0b00) = 0b0011.
    REQUIRE(*control == ((uint64_t{1} << 2) | (uint64_t{0b0011} << 20)));
}

TEST_CASE("debug register control ignores size for an execute watchpoint", "[debugger][watchpoint][encoding]") {
    const bb::watchpoint point{0xC000, 999, bb::watchpoint_condition::execute};
    const auto control = bb::debug_register_encoding::apply_to_control(0, 3, point);
    REQUIRE(control.has_value());

    // enable bit L3 (bit 6) set; the slot-3 field is zero (execute = 0b00, length forced to 0b00).
    REQUIRE(*control == (uint64_t{1} << 6));
}

TEST_CASE("debug register control rejects an unsupported data size", "[debugger][watchpoint][encoding]") {
    const bb::watchpoint point{0x4000, 3, bb::watchpoint_condition::write};
    REQUIRE_FALSE(bb::debug_register_encoding::apply_to_control(0, 0, point).has_value());
}

TEST_CASE("debug register control rejects an out-of-range slot", "[debugger][watchpoint][encoding]") {
    const bb::watchpoint point{0x4000, 4, bb::watchpoint_condition::write};
    REQUIRE_FALSE(bb::debug_register_encoding::apply_to_control(0, -1, point).has_value());
    REQUIRE_FALSE(bb::debug_register_encoding::apply_to_control(0, 4, point).has_value());
}

TEST_CASE("debug register control leaves other slots untouched", "[debugger][watchpoint][encoding]") {
    const bb::watchpoint slot_zero{0x4000, 4, bb::watchpoint_condition::write};
    const auto first = bb::debug_register_encoding::apply_to_control(0, 0, slot_zero);
    REQUIRE(first.has_value());

    const bb::watchpoint slot_one{0x8000, 1, bb::watchpoint_condition::read_write};
    const auto second = bb::debug_register_encoding::apply_to_control(*first, 1, slot_one);
    REQUIRE(second.has_value());

    // Both slots' bits are present and neither overwrote the other.
    const uint64_t expected = uint64_t{1} | (uint64_t{0b1101} << 16)
                            | (uint64_t{1} << 2) | (uint64_t{0b0011} << 20);
    REQUIRE(*second == expected);
}

TEST_CASE("clearing a debug register slot reverses applying it", "[debugger][watchpoint][encoding]") {
    const bb::watchpoint point{0x4000, 4, bb::watchpoint_condition::write};
    const auto armed = bb::debug_register_encoding::apply_to_control(0, 0, point);
    REQUIRE(armed.has_value());

    REQUIRE(bb::debug_register_encoding::clear_in_control(*armed, 0) == 0);
}

TEST_CASE("debug status decodes the slot that triggered", "[debugger][watchpoint][encoding]") {
    REQUIRE(bb::debug_register_encoding::triggered_slot(0) == -1);
    REQUIRE(bb::debug_register_encoding::triggered_slot(0b0001) == 0);
    REQUIRE(bb::debug_register_encoding::triggered_slot(0b0010) == 1);
    REQUIRE(bb::debug_register_encoding::triggered_slot(0b0100) == 2);
    REQUIRE(bb::debug_register_encoding::triggered_slot(0b1000) == 3);

    // Real DR6 keeps reserved high bits set; only the low four name a slot.
    REQUIRE(bb::debug_register_encoding::triggered_slot(0xFFFF0FF0) == -1);
    REQUIRE(bb::debug_register_encoding::triggered_slot(0xFFFF0FF4) == 2);

    // When several fire at once the lowest slot wins.
    REQUIRE(bb::debug_register_encoding::triggered_slot(0b1010) == 1);
}

TEST_CASE("clearing one slot keeps another slot armed", "[debugger][watchpoint][encoding]") {
    const bb::watchpoint slot_zero{0x4000, 4, bb::watchpoint_condition::write};
    const bb::watchpoint slot_one{0x8000, 1, bb::watchpoint_condition::read_write};
    auto control = bb::debug_register_encoding::apply_to_control(0, 0, slot_zero);
    control = bb::debug_register_encoding::apply_to_control(*control, 1, slot_one);
    REQUIRE(control.has_value());

    const uint64_t after_clear = bb::debug_register_encoding::clear_in_control(*control, 0);

    // Slot 0 gone, slot 1 still present.
    const uint64_t slot_one_only = (uint64_t{1} << 2) | (uint64_t{0b0011} << 20);
    REQUIRE(after_clear == slot_one_only);
}
