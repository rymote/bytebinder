#pragma once

struct vmt_target {
    virtual ~vmt_target() = default;
    virtual int compute(int input) { return input + 1; }
};
