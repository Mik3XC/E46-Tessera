#include "e46/rad.hpp"
#include <algorithm>
#include <stdexcept>

namespace e46::rad
{
namespace
{
void put64 (std::uint8_t *out, std::uint64_t n)
{
    for (unsigned i = 0; i < 8; ++i)
        out[i] = static_cast<std::uint8_t>(n >> (8 * i));
}
std::uint64_t get64 (const std::uint8_t *in)
{
    std::uint64_t n = 0;
    for (unsigned i = 0; i < 8; ++i)
        n |= std::uint64_t(in[i]) << (8 * i);
    return n;
}
void check_z (unsigned z)
{
    if (z > 128)
        throw std::invalid_argument("Z exceeds digest width");
}
} // namespace
Candidate candidate (std::uint64_t index)
{
    Candidate out{};
    put64(out.data(), index);
    return out;
}
std::optional<std::uint64_t> candidate_index (const Candidate &value)
{
    if (std::any_of(value.begin() + 8, value.end(),
                    [] (auto b)
                    {
                        return b != 0;
                    }))
        return std::nullopt;
    return get64(value.data());
}
Payload stamp (const Context &context, const Payload &miner, std::uint64_t nonce)
{
    std::array<std::uint8_t, 80> bytes{};
    std::copy(context.previous.begin(), context.previous.end(), bytes.begin());
    put64(bytes.data() + 32, context.window);
    std::copy(miner.begin(), miner.end(), bytes.begin() + 40);
    put64(bytes.data() + 72, nonce);
    return shake::shake256_tagged_256("E46-rad", bytes);
}
Digest candidate_hash (const Payload &s, const Candidate &value)
{
    std::array<std::uint8_t, 48> bytes{};
    std::copy(s.begin(), s.end(), bytes.begin());
    std::copy(value.begin(), value.end(), bytes.begin() + 32);
    return rl::rl_v3_128(bytes);
}
unsigned z_level (const Digest &a, const Digest &b) noexcept
{
    unsigned n = 0;
    for (unsigned i = 0; i < 16; ++i)
    {
        unsigned delta = a[i] ^ b[i];
        if (delta == 0)
            n += 8;
        else
        {
            for (unsigned bit = 128; (delta & bit) == 0; bit >>= 1)
                ++n;
            break;
        }
    }
    return n;
}
unsigned byte_tier (unsigned z)
{
    check_z(z);
    return z / 8 * 8;
}
unsigned collision_tier (unsigned z)
{
    return byte_tier(z) + 8;
}
Encoded encode (const Rad &rad)
{
    check_z(rad.z);
    Encoded out{};
    out[0] = 2;
    std::copy(rad.miner.begin(), rad.miner.end(), out.begin() + 1);
    put64(out.data() + 33, rad.window);
    put64(out.data() + 41, rad.nonce);
    std::copy(rad.a.begin(), rad.a.end(), out.begin() + 49);
    std::copy(rad.b.begin(), rad.b.end(), out.begin() + 65);
    out[81] = static_cast<std::uint8_t>(rad.z);
    return out;
}
Rad decode (Bytes bytes)
{
    if (bytes.size() != 82 || bytes[0] != 2 || bytes[81] > 128)
        throw std::invalid_argument("Invalid Rad encoding");
    Rad out{};
    std::copy_n(bytes.begin() + 1, 32, out.miner.begin());
    out.window = get64(bytes.data() + 33);
    out.nonce = get64(bytes.data() + 41);
    std::copy_n(bytes.begin() + 49, 16, out.a.begin());
    std::copy_n(bytes.begin() + 65, 16, out.b.begin());
    out.z = bytes[81];
    return out;
}
Digest id (const Context &context, const Rad &rad)
{
    // Derive from the event's declared window; verify establishes context equality.
    auto s = stamp({context.previous, rad.window}, rad.miner, rad.nonce);
    std::array<std::uint8_t, 64> bytes{};
    std::copy(s.begin(), s.end(), bytes.begin());
    std::copy(rad.a.begin(), rad.a.end(), bytes.begin() + 32);
    std::copy(rad.b.begin(), rad.b.end(), bytes.begin() + 48);
    return rl::rl_v3_128(bytes);
}
bool verify (const Context &context, const Policy &policy, const Rad &rad)
{
    check_z(policy.minimum_z);
    if (policy.candidates < 2)
        throw std::invalid_argument("Candidate domain too small");
    if (rad.window != context.window || rad.z < policy.minimum_z || rad.z > 128)
        return false;
    const auto a = candidate_index(rad.a), b = candidate_index(rad.b);
    if (!a || !b || *a >= *b || *b >= policy.candidates)
        return false;
    auto s = stamp(context, rad.miner, rad.nonce);
    return z_level(candidate_hash(s, rad.a), candidate_hash(s, rad.b)) == rad.z;
}
merkle::Event checked_event (const Context &context, const Policy &policy, const Rad &rad)
{
    if (!verify(context, policy, rad))
        throw std::invalid_argument("Invalid Rad");
    const auto raw = encode(rad);
    const auto key = id(context, rad);
    return {2, {key.begin(), key.end()}, {raw.begin() + 1, raw.end()}};
}
Digest commit_hash (const Payload &commitment, std::uint64_t nonce)
{
    constexpr char tag[] = "E46-commit-pow";
    std::array<std::uint8_t, 55> bytes{};
    std::copy_n(tag, sizeof(tag), bytes.begin());
    std::copy(commitment.begin(), commitment.end(), bytes.begin() + sizeof(tag));
    put64(bytes.data() + 47, nonce);
    return rl::rl_v3_128(bytes);
}
bool commit_valid (const Payload &commitment, std::uint64_t nonce, unsigned minimum_z)
{
    check_z(minimum_z);
    return z_level(commit_hash(commitment, nonce), Digest{}) >= minimum_z;
}
} // namespace e46::rad
