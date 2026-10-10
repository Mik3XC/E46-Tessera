#include "e46/header.hpp"
#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>

namespace e46::chain
{
namespace
{
using Wide = unsigned __int128;
using SignedWide = __int128;
using WideBytes = std::array<std::uint8_t, 40>; // little-endian; target * ASERT factor is < 2^248

void put_le (std::uint8_t *out, std::uint64_t value, std::size_t count) noexcept
{
    for (std::size_t i = 0; i < count; ++i)
    {
        out[i] = static_cast<std::uint8_t>(value);
        value >>= 8;
    }
}

std::uint64_t get_le (const std::uint8_t *in, std::size_t count) noexcept
{
    std::uint64_t value = 0;
    for (std::size_t i = count; i-- > 0;)
        value = (value << 8) | in[i];
    return value;
}

int compare (const Target256 &a, const Target256 &b) noexcept
{
    if (std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end()))
        return -1;
    if (std::lexicographical_compare(b.begin(), b.end(), a.begin(), a.end()))
        return 1;
    return 0;
}

const Target256 &max_target ()
{
    static const Target256 value = []
    {
        Target256 out{};
        out[3] = 0x7f;
        out[4] = 0xff;
        out[5] = 0xff;
        return out;
    }();
    return value;
}

WideBytes multiply (const Target256 &target, std::uint64_t factor) noexcept
{
    WideBytes out{};
    Wide carry = 0;
    for (std::size_t i = 0; i < target.size(); ++i)
    {
        const auto product = static_cast<Wide>(target[target.size() - 1 - i]) * factor + carry;
        out[i] = static_cast<std::uint8_t>(product);
        carry = product >> 8;
    }
    std::size_t i = target.size();
    while (carry != 0 && i < out.size())
    {
        out[i++] = static_cast<std::uint8_t>(carry);
        carry >>= 8;
    }
    return out;
}

unsigned bit_length (const WideBytes &value) noexcept
{
    for (std::size_t i = value.size(); i-- > 0;)
        if (value[i] != 0)
        {
            unsigned bits = 0;
            auto byte = value[i];
            while (byte != 0)
            {
                ++bits;
                byte >>= 1;
            }
            return static_cast<unsigned>(i * 8) + bits;
        }
    return 0;
}

WideBytes shift_left (const WideBytes &value, unsigned count) noexcept
{
    WideBytes out{};
    const auto byte_shift = count / 8;
    const auto bit_shift = count % 8;
    for (std::size_t i = 0; i < value.size(); ++i)
    {
        if (i + byte_shift < out.size())
            out[i + byte_shift] |= static_cast<std::uint8_t>(value[i] << bit_shift);
        if (bit_shift != 0 && i + byte_shift + 1 < out.size())
            out[i + byte_shift + 1] |= static_cast<std::uint8_t>(value[i] >> (8 - bit_shift));
    }
    return out;
}

WideBytes shift_right (const WideBytes &value, unsigned count) noexcept
{
    WideBytes out{};
    const auto byte_shift = count / 8;
    const auto bit_shift = count % 8;
    for (std::size_t i = byte_shift; i < value.size(); ++i)
    {
        const auto j = i - byte_shift;
        out[j] |= static_cast<std::uint8_t>(value[i] >> bit_shift);
        if (bit_shift != 0 && i + 1 < value.size())
            out[j] |= static_cast<std::uint8_t>(value[i + 1] << (8 - bit_shift));
    }
    return out;
}

Target256 low_target (const WideBytes &value) noexcept
{
    Target256 out{};
    for (std::size_t i = 0; i < out.size(); ++i)
        out[out.size() - 1 - i] = value[i];
    return out;
}

void append_u32 (std::array<std::uint8_t, rl::header_bytes> &out, std::size_t &offset,
                 std::uint32_t value) noexcept
{
    put_le(out.data() + offset, value, 4);
    offset += 4;
}
} // namespace

std::array<std::uint8_t, rl::header_bytes> serialize_header (const Header &header) noexcept
{
    std::array<std::uint8_t, rl::header_bytes> out{};
    std::size_t offset = 0;
    append_u32(out, offset, header.version);
    for (const auto *field : {&header.prev_block, &header.merkle_root, &header.event_root})
    {
        std::copy(field->begin(), field->end(), out.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += field->size();
    }
    put_le(out.data() + offset, header.time, 8);
    offset += 8;
    append_u32(out, offset, header.bits);
    put_le(out.data() + offset, header.nonce, 8);
    return out;
}

Header deserialize_header (rl::Bytes bytes)
{
    if (bytes.size() != rl::header_bytes)
        throw std::invalid_argument("E46 header must be exactly 120 bytes");
    Header header{};
    std::size_t offset = 0;
    header.version = static_cast<std::uint32_t>(get_le(bytes.data() + offset, 4));
    offset += 4;
    for (auto *field : {&header.prev_block, &header.merkle_root, &header.event_root})
    {
        std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset), field->size(), field->begin());
        offset += field->size();
    }
    header.time = get_le(bytes.data() + offset, 8);
    offset += 8;
    header.bits = static_cast<std::uint32_t>(get_le(bytes.data() + offset, 4));
    offset += 4;
    header.nonce = get_le(bytes.data() + offset, 8);
    return header;
}

Target256 compact_to_target (std::uint32_t bits)
{
    const auto size = bits >> 24;
    const auto word = bits & 0x007fffffU;
    if ((bits & 0x00800000U) != 0 || word == 0 || size == 0 || size > 32)
        throw std::invalid_argument("invalid compact target");
    Target256 out{};
    if (size <= 3)
    {
        const auto value = word >> (8 * (3 - size));
        for (std::uint32_t i = 0; i < size; ++i)
            out[31 - i] = static_cast<std::uint8_t>(value >> (8 * i));
    }
    else
    {
        const auto offset = 32U - size;
        out[offset] = static_cast<std::uint8_t>(word >> 16);
        out[offset + 1] = static_cast<std::uint8_t>(word >> 8);
        out[offset + 2] = static_cast<std::uint8_t>(word);
    }
    if (target_to_compact(out) != bits || compare(out, max_target()) > 0)
        throw std::invalid_argument("noncanonical or above-pow-limit compact target");
    return out;
}

std::uint32_t target_to_compact (const Target256 &target)
{
    if (std::all_of(target.begin(), target.end(), [] (std::uint8_t byte) { return byte == 0; }) ||
        compare(target, max_target()) > 0)
        throw std::invalid_argument("target must be in [1, MAX_TARGET]");
    std::size_t first = 0;
    while (target[first] == 0)
        ++first;
    std::uint32_t size = static_cast<std::uint32_t>(target.size() - first);
    std::uint32_t word = 0;
    if (size <= 3)
    {
        for (std::size_t i = first; i < target.size(); ++i)
            word = (word << 8) | target[i];
        word <<= 8 * (3 - size);
    }
    else
    {
        word = (static_cast<std::uint32_t>(target[first]) << 16) |
               (static_cast<std::uint32_t>(target[first + 1]) << 8) |
               target[first + 2];
    }
    if ((word & 0x00800000U) != 0)
    {
        word >>= 8;
        ++size;
    }
    return (size << 24) | (word & 0x007fffffU);
}

Target256 asert_target (const Target256 &anchor_target, std::uint64_t anchor_height,
                        std::uint64_t anchor_parent_time, std::uint64_t parent_height,
                        std::uint64_t parent_time)
{
    if (compare(anchor_target, max_target()) > 0 ||
        std::all_of(anchor_target.begin(), anchor_target.end(), [] (std::uint8_t byte) { return byte == 0; }))
        throw std::invalid_argument("ASERT anchor target must be in [1, MAX_TARGET]");
    if (parent_height < anchor_height)
        throw std::invalid_argument("parent precedes ASERT anchor");

    const SignedWide time_diff = static_cast<SignedWide>(parent_time) - anchor_parent_time;
    const SignedWide block_delta = static_cast<SignedWide>(parent_height - anchor_height) + 1;
    const SignedWide error = time_diff - static_cast<SignedWide>(target_spacing) * block_delta;
    const SignedWide exponent = (error * 65536) / asert_half_life; // C++ signed division truncates toward zero
    const auto shifts = exponent >> 16; // C++20 signed shift is arithmetic (rounds down)
    const auto frac = static_cast<std::uint32_t>(static_cast<Wide>(exponent) & 0xffffU);
    const Wide f = frac;
    const Wide polynomial = static_cast<Wide>(195766423245049ULL) * f +
                            static_cast<Wide>(971821376ULL) * f * f +
                            static_cast<Wide>(5127ULL) * f * f * f + (static_cast<Wide>(1) << 47);
    const auto factor = static_cast<std::uint64_t>(65536 + (polynomial >> 48));
    const auto product = multiply(anchor_target, factor);

    Target256 result{};
    if (shifts >= 16)
    {
        const auto left = shifts - 16;
        if (bit_length(product) + static_cast<unsigned>(std::min<SignedWide>(left, 1000)) > 256 || left >= 320)
            return max_target();
        const auto shifted = shift_left(product, static_cast<unsigned>(left));
        result = low_target(shifted);
    }
    else
    {
        const auto right = 16 - shifts;
        if (right >= static_cast<SignedWide>(product.size() * 8))
        {
            Target256 one{};
            one.back() = 1;
            return one;
        }
        result = low_target(shift_right(product, static_cast<unsigned>(right)));
    }

    if (std::all_of(result.begin(), result.end(), [] (std::uint8_t byte) { return byte == 0; }))
    {
        result.back() = 1;
        return result;
    }
    if (compare(result, max_target()) > 0)
        return max_target();
    return result;
}

std::uint32_t asert_bits (std::uint32_t anchor_bits, std::uint64_t anchor_height,
                          std::uint64_t anchor_parent_time, std::uint64_t parent_height,
                          std::uint64_t parent_time)
{
    return target_to_compact(asert_target(compact_to_target(anchor_bits), anchor_height,
                                         anchor_parent_time, parent_height, parent_time));
}

bool check_header_pow (const Header &header)
{
    const auto target = compact_to_target(header.bits);
    const auto bytes = serialize_header(header);
    return rl::rl_v3_header_pow(bytes, target);
}

bool check_block_time (std::uint64_t new_time, std::span<const std::uint64_t> previous_times,
                       std::uint64_t adjusted_time)
{
    if (previous_times.empty() || previous_times.size() > 11)
        throw std::invalid_argument("MTP requires 1 to 11 previous block times");
    std::array<std::uint64_t, 11> ordered{};
    std::copy(previous_times.begin(), previous_times.end(), ordered.begin());
    std::sort(ordered.begin(), ordered.begin() + static_cast<std::ptrdiff_t>(previous_times.size()));
    const auto median = ordered[previous_times.size() / 2];
    if (new_time <= median)
        return false;
    const auto future_limit = adjusted_time > std::numeric_limits<std::uint64_t>::max() - max_future_seconds
                                  ? std::numeric_limits<std::uint64_t>::max()
                                  : adjusted_time + max_future_seconds;
    return new_time <= future_limit;
}
} // namespace e46::chain
