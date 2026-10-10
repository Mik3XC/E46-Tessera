#pragma once

#include "e46/shake.hpp"
#include <cstdint>
#include <span>
#include <string_view>

namespace e46::checkpoints
{
struct Checkpoint
{
    std::uint64_t height;
    std::string_view block_id;
};

std::span<const Checkpoint> testnet () noexcept;
void validate_testnet (std::uint64_t height, const shake::Digest256 &block_id);
} // namespace e46::checkpoints
