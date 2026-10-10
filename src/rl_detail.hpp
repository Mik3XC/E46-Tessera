#pragma once
#include "e46/rl.hpp"
#include <bit>
#include <stdexcept>
#include <utility>

namespace e46::rl::detail
{
using U128 = unsigned __int128;
using I128 = __int128;
using Words = std::array<std::uint64_t, 4>;
static_assert((I128{-1} >> 1) == -1);
inline std::pair<I128, std::uint64_t> floor_divmod (I128 z) noexcept
{
    // C++20 signed right shift rounds toward -infinity, as the spec requires.
    return {z >> 64, static_cast<std::uint64_t>(z)};
}
template <std::size_t L>
inline void lane (const Words &x, const Words &v, std::uint64_t i, std::int64_t d, Words &nx,
                  Words &nv) noexcept
{
    constexpr auto N = (L + 1) % 4;
    const I128 z = I128{257} * x[L] + I128{17} * v[L] + I128{d} * (I128{i} + L + 1) +
                   std::rotl(x[N], 11 + 7 * L);
    const auto [q, r] = floor_divmod(z <= 0 ? z - 16 : z + 15);
    const auto sum = std::uint64_t{65537} * v[L] + static_cast<std::uint64_t>(q) +
                     static_cast<std::uint64_t>(d) + i + L + 1 + v[N];
    nv[L] = std::rotl(sum, 13 + 8 * L) ^ r;
    nx[L] = r ^ std::rotl(nv[L], static_cast<int>((i + 11 * L) % 63 + 1));
}
inline void step (Words &x, Words &v, std::uint64_t &i, bool bit) noexcept
{
    Words nx{}, nv{};
    const std::int64_t d = bit ? 16 : -16;
    lane<0>(x, v, i, d, nx, nv);
    lane<1>(x, v, i, d, nx, nv);
    lane<2>(x, v, i, d, nx, nv);
    lane<3>(x, v, i, d, nx, nv);
    x = nx;
    v = nv;
    ++i;
}
inline void absorb (Words &x, Words &v, std::uint64_t &i, std::uint8_t byte) noexcept
{
    for (int shift = 7; shift >= 0; --shift)
        step(x, v, i, ((byte >> shift) & 1) != 0);
}
inline std::uint8_t xtime (std::uint8_t x) noexcept
{
    return static_cast<std::uint8_t>((x << 1) ^ ((x & 128) ? 0x11d : 0));
}
inline std::uint8_t coefficient (std::uint8_t x, std::size_t shard) noexcept
{
    switch (shard)
    {
    case 0:
        return x;
    case 1:
        return xtime(x);
    case 2:
        return x ^ xtime(x);
    default:
        return xtime(xtime(x));
    }
}
inline void check_length (std::uint64_t n)
{
    if (n > max_message_bytes)
        throw std::length_error("RL message exceeds step-counter limit");
}
inline void prefix (Words &x, Words &v, std::uint64_t &i, std::uint64_t n) noexcept
{
    for (int shift = 56; shift >= 0; shift -= 8)
        absorb(x, v, i, static_cast<std::uint8_t>(n >> shift));
}
inline U128 rot128 (U128 x, unsigned n) noexcept
{
    return n ? (x << n) | (x >> (128 - n)) : x;
}
inline Result output (const Words &x, const Words &v) noexcept
{
    Result out{};
    U128 folded = 0;
    constexpr std::array<unsigned, 4> rotation{0, 29, 61, 97};
    for (std::size_t l = 0; l < 4; ++l)
    {
        const U128 word = (U128{x[l]} << 64) | v[l];
        folded ^= rot128(word, rotation[l]);
        for (unsigned j = 0; j < 16; ++j)
            out.unfolded[16 * l + j] = static_cast<std::uint8_t>(word >> (120 - 8 * j));
    }
    for (unsigned j = 0; j < 16; ++j)
        out.folded[j] = static_cast<std::uint8_t>(folded >> (120 - 8 * j));
    return out;
}
} // namespace e46::rl::detail
