#pragma once
#include "e46/rl.hpp"
#include <stdexcept>
#include <string>
#include <string_view>

namespace e46::rl::tool
{
inline unsigned nibble (char c)
{
    if (c >= '0' && c <= '9')
        return static_cast<unsigned>(c - '0');
    if (c >= 'a' && c <= 'f')
        return static_cast<unsigned>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F')
        return static_cast<unsigned>(c - 'A' + 10);
    throw std::invalid_argument("Non-hexadecimal input");
}
inline std::vector<std::uint8_t> unhex (std::string_view s)
{
    if (s.size() % 2)
        throw std::invalid_argument("Odd hexadecimal length");
    std::vector<std::uint8_t> out(s.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i)
        out[i] = static_cast<std::uint8_t>((nibble(s[2 * i]) << 4) | nibble(s[2 * i + 1]));
    return out;
}
inline std::string hex (Bytes bytes)
{
    constexpr char chars[] = "0123456789abcdef";
    std::string out;
    out.reserve(2 * bytes.size());
    for (auto b : bytes)
    {
        out.push_back(chars[b >> 4]);
        out.push_back(chars[b & 15]);
    }
    return out;
}
} // namespace e46::rl::tool
