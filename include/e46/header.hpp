#pragma once

#include "e46/rl.hpp"
#include <array>
#include <cstdint>
#include <span>

namespace e46::chain
{
using Target256 = rl::Target256;

inline constexpr std::uint64_t target_spacing = 150;
inline constexpr std::uint64_t asert_half_life = 7200;
inline constexpr std::uint64_t max_future_seconds = 900;
inline constexpr std::uint32_t max_target_bits = 0x1d7fffff;

struct Header
{
    std::uint32_t version{};
    std::array<std::uint8_t, 32> prev_block{};
    std::array<std::uint8_t, 32> merkle_root{};
    std::array<std::uint8_t, 32> event_root{};
    std::uint64_t time{};
    std::uint32_t bits{};
    std::uint64_t nonce{};
};

std::array<std::uint8_t, rl::header_bytes> serialize_header (const Header &header) noexcept;
Header deserialize_header (rl::Bytes bytes);

Target256 compact_to_target (std::uint32_t bits);
std::uint32_t target_to_compact (const Target256 &target);
Target256 asert_target (const Target256 &anchor_target, std::uint64_t anchor_height,
                        std::uint64_t anchor_parent_time, std::uint64_t parent_height,
                        std::uint64_t parent_time);
std::uint32_t asert_bits (std::uint32_t anchor_bits, std::uint64_t anchor_height,
                          std::uint64_t anchor_parent_time, std::uint64_t parent_height,
                          std::uint64_t parent_time);

bool check_header_pow (const Header &header);
bool check_block_time (std::uint64_t new_time, std::span<const std::uint64_t> previous_times,
                       std::uint64_t adjusted_time);
} // namespace e46::chain
