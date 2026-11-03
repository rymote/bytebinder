/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_api.h"
#include "bb_chain_step.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace bytebinder {
    /**
     * @brief A static base plus a list of offsets that resolve to a target
     *        address. Resolution adds each offset to the running address and
     *        dereferences after every offset except the last, which matches the
     *        chain_step walk: feed to_chain_steps() to process::resolve_chain or
     *        watch_chain. The base is a static address (inside a loaded module),
     *        so the path survives restarts of the target once rebased against
     *        the module load address.
     */
    struct BYTEBINDER_API pointer_path {
        uintptr_t base = 0;
        std::vector<ptrdiff_t> offsets;

        /// @brief The number of pointer dereferences the path performs.
        [[nodiscard]] size_t depth() const noexcept {
            return offsets.empty() ? 0 : offsets.size() - 1;
        }

        /// @brief Converts the path to chain_step hops: every offset dereferences
        ///        except the last, whose value the caller reads separately.
        [[nodiscard]] std::vector<chain_step> to_chain_steps() const {
            std::vector<chain_step> steps;
            steps.reserve(offsets.size());
            for (size_t offset_index = 0; offset_index < offsets.size(); ++offset_index) {
                chain_step step;
                step.offset = offsets[offset_index];
                step.dereference = offset_index + 1 < offsets.size();
                steps.push_back(step);
            }
            return steps;
        }
    };
}
