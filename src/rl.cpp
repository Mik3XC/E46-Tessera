#include "rl_detail.hpp"
#include <algorithm>
#include <limits>

namespace e46::rl
{
namespace
{
Result hash (Bytes message, Version version)
{
    detail::check_length(message.size());
    detail::Words x{0, 1, 2, 3}, v{1, 3, 5, 7};
    std::uint64_t i = 0;
    const auto n = message.size();
    const auto s = n / 4 + (n % 4 != 0);
    detail::prefix(x, v, i, n);
    for (auto byte : message)
        detail::absorb(x, v, i, byte);
    for (auto j = n; j < 4 * s; ++j)
        detail::absorb(x, v, i, 0);
    // Two passes over input avoid heap allocation and a materialized record.
    const auto at = [&] (std::size_t j)
    {
        return j < n ? message[j] : std::uint8_t{0};
    };
    for (std::size_t j = 0; j < s; ++j)
        detail::absorb(x, v, i, at(j) ^ at(s + j) ^ at(2 * s + j) ^ at(3 * s + j));
    for (std::size_t j = 0; j < s; ++j)
        detail::absorb(x, v, i,
                       at(j) ^ detail::xtime(at(s + j)) ^ detail::coefficient(at(2 * s + j), 2) ^
                           detail::coefficient(at(3 * s + j), 3));
    if (version == Version::v3)
        detail::absorb(x, v, i, 0);
    return detail::output(x, v);
}
} // namespace
Digest128 rl_v3_128 (Bytes message)
{
    return hash(message, Version::v3).folded;
}
Digest512 rl_v3_unfolded (Bytes message)
{
    return hash(message, Version::v3).unfolded;
}
Digest128 rl_v2_128 (Bytes message)
{
    return hash(message, Version::v2).folded;
}
Digest512 rl_v2_unfolded (Bytes message)
{
    return hash(message, Version::v2).unfolded;
}

Hasher::Hasher (std::uint64_t total, Version version)
    : total_(total), shard_size_(0), version_(version)
{
    detail::check_length(total);
    if (version != Version::v2 && version != Version::v3)
        throw std::invalid_argument("Unknown RL version");
    const auto shard = total / 4 + (total % 4 != 0);
    if (shard > std::numeric_limits<std::size_t>::max() / 4 || shard > parity_.max_size() / 2)
        throw std::length_error("RL parity shards exceed addressable memory");
    shard_size_ = static_cast<std::size_t>(shard);
    parity_.resize(2 * shard_size_);
    detail::prefix(x_, v_, step_, total);
}
void Hasher::update (Bytes chunk)
{
    if (finalized_)
        throw std::logic_error("RL update after finalize");
    if (chunk.size() > total_ - received_)
        throw std::length_error("RL input exceeds declared length");
    for (auto byte : chunk)
    {
        const auto shard = static_cast<std::size_t>(received_ / shard_size_);
        const auto column = static_cast<std::size_t>(received_ % shard_size_);
        parity_[column] ^= byte;
        parity_[shard_size_ + column] ^= detail::coefficient(byte, shard);
        detail::absorb(x_, v_, step_, byte);
        ++received_;
    }
}
Result Hasher::finalize ()
{
    if (finalized_)
        return result_;
    if (received_ != total_)
        throw std::logic_error("RL input shorter than declared length");
    for (auto n = total_; n < 4 * shard_size_; ++n)
        detail::absorb(x_, v_, step_, 0);
    for (auto byte : parity_)
        detail::absorb(x_, v_, step_, byte);
    if (version_ == Version::v3)
        detail::absorb(x_, v_, step_, 0);
    result_ = detail::output(x_, v_);
    finalized_ = true;
    return result_;
}
bool meets_target (const Digest128 &digest, const Target256 &target) noexcept
{
    return !std::lexicographical_compare(target.begin(), target.begin() + 16, digest.begin(),
                                         digest.end());
}
bool rl_v3_header_pow (Bytes header, const Target256 &target)
{
    if (header.size() != header_bytes)
        throw std::invalid_argument("RL PoW header must be exactly 120 bytes");
    return meets_target(rl_v3_128(header), target);
}
} // namespace e46::rl
