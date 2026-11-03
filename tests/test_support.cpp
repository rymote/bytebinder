#include "test_support.h"

#include "bb_macros.h"

uint8_t buffer[1024];

volatile int bytebinder_test_marker_observable = 0;

extern "C" NOINLINE void bytebinder_test_marker_function() {
    bytebinder_test_marker_observable += 1;
}
