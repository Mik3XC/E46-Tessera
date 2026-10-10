#pragma once
#include "e46/merkle.hpp"
#include "e46/rl.hpp"
#include <optional>

namespace e46::rad
{
using Digest = rl::Digest128;
using Payload = shake::Digest256;
using Candidate = Digest;
using Bytes = rl::Bytes;
struct Context
{
    Payload previous{};
    std::uint64_t window{};
};
struct Policy
{
    std::uint64_t candidates;
    unsigned minimum_z;
};
struct Rad
{
    Payload miner{};
    std::uint64_t window{}, nonce{};
    Candidate a{}, b{};
    unsigned z{};
};
using Encoded = std::array<std::uint8_t, 82>;
Candidate candidate (std::uint64_t index);
std::optional<std::uint64_t> candidate_index (const Candidate &value);
Payload stamp (const Context &context, const Payload &miner, std::uint64_t nonce);
Digest candidate_hash (const Payload &stamp, const Candidate &value);
unsigned z_level (const Digest &a, const Digest &b) noexcept;
unsigned byte_tier (unsigned z);
// Strictly NEXT tier. Returns 136 for base 128: no digest can reach it.
unsigned collision_tier (unsigned minimum_z);
Encoded encode (const Rad &rad);
Rad decode (Bytes bytes);
Digest id (const Context &context, const Rad &rad);
// Caller supplies authenticated parent/window and runtime S/Z policy.
// Invalid policy throws; invalid Rad returns false. Crypto errors propagate.
bool verify (const Context &context, const Policy &policy, const Rad &rad);
merkle::Event checked_event (const Context &context, const Policy &policy, const Rad &rad);
Digest commit_hash (const Payload &commitment, std::uint64_t nonce);
bool commit_valid (const Payload &commitment, std::uint64_t nonce, unsigned minimum_z);
} // namespace e46::rad
