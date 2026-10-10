#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace e46::rl
{
static_assert(sizeof(std::size_t) >= 8, "WO-01 currently supports 64-bit platforms");
using Bytes = std::span<const std::uint8_t>;
using Digest128 = std::array<std::uint8_t, 16>;
using Digest512 = std::array<std::uint8_t, 64>;
using Target256 = std::array<std::uint8_t, 32>;
enum class Version
{
    v2,
    v3
};
struct Result
{
    Digest128 folded;
    Digest512 unfolded;
};
// Bound counter arithmetic, including i+33, before any allocation or hashing.
inline constexpr std::uint64_t max_message_bytes = ((UINT64_MAX - 136) / 48) * 4;
inline constexpr std::size_t header_bytes = 120;

// Digests are canonical big-endian bytes, independent of host byte order.
Digest128 rl_v3_128 (Bytes message);
Digest512 rl_v3_unfolded (Bytes message);
// Legacy reference compatibility, not the chain's selected hash version.
Digest128 rl_v2_128 (Bytes message);
Digest512 rl_v2_unfolded (Bytes message);

class Hasher
{
public:
    // The record commits to length first. Streaming needs it before update().
    // Stores two parity shards (2*ceil(length/4) bytes); does not retain message.
    explicit Hasher (std::uint64_t total_bytes, Version version = Version::v3);
    // Copies are independent snapshots. Declaring these suppresses a default
    // move that would otherwise leave the source with missing parity buffers.
    Hasher (const Hasher &) = default;
    Hasher &operator=(const Hasher &) = default;
    void update (Bytes chunk);
    // Idempotent once successful; rejects incomplete input. update after finish
    // and excess input throw; these rejected operations do not change state.
    Result finalize ();
    std::uint64_t bytes_received () const noexcept
    {
        return received_;
    }

private:
    std::array<std::uint64_t, 4> x_{0, 1, 2, 3}, v_{1, 3, 5, 7};
    std::uint64_t step_ = 0, total_, received_ = 0;
    std::size_t shard_size_;
    Version version_;
    std::vector<std::uint8_t> parity_;
    bool finalized_ = false;
    Result result_{};
};

// CHAIN-DESIGN §2b: compare folded digest <= TOP 128 bits of a BE256 target.
// Low target bits intentionally do not participate. Compact-bits/ASERT are WO-06.
bool meets_target (const Digest128 &digest, const Target256 &target) noexcept;
bool rl_v3_header_pow (Bytes serialized_header, const Target256 &target);
} // namespace e46::rl
