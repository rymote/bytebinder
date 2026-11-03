#pragma once

// Polymorphic type with enough virtual slots that its vtable is a run of at
// least four code pointers on both the Itanium and MSVC ABIs.
struct vtable_probe {
    virtual ~vtable_probe() = default;
    virtual int first(int input) { return input + 1; }
    virtual int second(int input) { return input + 2; }
    virtual int third(int input) { return input + 3; }
};
