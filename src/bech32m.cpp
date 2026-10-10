#include "e46/bech32m.hpp"
#include <algorithm>
#include <array>
#include <stdexcept>

namespace e46::bech32m
{
namespace
{
constexpr std::string_view alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
constexpr std::uint32_t residue = 0x2bc830a3;
constexpr std::array<std::uint32_t, 5> generators{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd,
                                                  0x2a1462b3};
constexpr std::array<std::string_view, 10> prefixes{
    "e46", "te46", "tes", "tess", "e46tx", "te46tx", "e46blk", "te46blk", "e46rad", "te46rad"};

[[noreturn]] void reject (const char *message)
{
    throw std::invalid_argument(message);
}

std::string normalize (std::string_view text)
{
    bool upper = false, lower = false;
    std::string result;
    result.reserve(text.size());
    for (const unsigned char c : text)
    {
        if (c < 33 || c > 126)
            reject("Bech32m requires printable ASCII");
        lower |= c >= 'a' && c <= 'z';
        upper |= c >= 'A' && c <= 'Z';
        result.push_back(static_cast<char>(c >= 'A' && c <= 'Z' ? c + 32 : c));
    }
    if (upper && lower)
        reject("Bech32m mixed case");
    return result;
}

std::string checked_hrp (std::string_view hrp)
{
    if (hrp.empty() || hrp.size() > 83)
        reject("Bech32m HRP length");
    return normalize(hrp);
}

void require_e46_prefix (std::string_view hrp)
{
    if (std::find(prefixes.begin(), prefixes.end(), hrp) == prefixes.end())
        reject("Unknown E46 prefix");
}

std::uint32_t advance (std::uint32_t state, std::uint8_t word)
{
    const auto high = state >> 25;
    state = ((state & 0x1ffffff) << 5) ^ word;
    for (unsigned j = 0; j < generators.size(); ++j)
        state ^= generators[j] & (std::uint32_t{0} - ((high >> j) & 1));
    return state;
}

std::uint32_t hrp_state (std::string_view hrp)
{
    std::uint32_t state = 1;
    for (const unsigned char c : hrp)
        state = advance(state, c >> 5);
    state = advance(state, 0);
    for (const unsigned char c : hrp)
        state = advance(state, c & 31);
    return state;
}
} // namespace

std::string encode_raw (std::string_view input_hrp, Bytes words)
{
    const auto hrp = checked_hrp(input_hrp);
    if (words.size() > 83 - hrp.size())
        reject("Bech32m exceeds 90 characters");
    std::string out = hrp + '1';
    out.reserve(hrp.size() + 7 + words.size());
    auto check = hrp_state(hrp);
    for (auto word : words)
    {
        if (word > 31)
            reject("Bech32m word exceeds five bits");
        check = advance(check, word);
        out.push_back(alphabet[word]);
    }
    for (unsigned j = 0; j < 6; ++j)
        check = advance(check, 0);
    check ^= residue;
    for (int shift = 25; shift >= 0; shift -= 5)
        out.push_back(alphabet[(check >> shift) & 31]);
    return out;
}

RawDecoded decode_raw (std::string_view encoded)
{
    if (encoded.size() < 8 || encoded.size() > 90)
        reject("Bech32m encoded length");
    const auto text = normalize(encoded);
    const auto split = text.rfind('1');
    if (split == std::string::npos || split == 0 || split + 7 > text.size())
        reject("Bech32m separator/checksum length");
    RawDecoded out{text.substr(0, split), {}};
    auto check = hrp_state(out.hrp);
    for (std::size_t j = split + 1; j < text.size(); ++j)
    {
        const auto digit = alphabet.find(text[j]);
        if (digit == std::string_view::npos)
            reject("Bech32m alphabet");
        check = advance(check, static_cast<std::uint8_t>(digit));
        if (j < text.size() - 6)
            out.words.push_back(static_cast<std::uint8_t>(digit));
    }
    if (check != residue)
        reject("Bech32m checksum");
    return out;
}

std::string encode_e46 (std::string_view input_hrp, std::uint8_t version, Bytes payload)
{
    const auto hrp = checked_hrp(input_hrp);
    require_e46_prefix(hrp);
    if (version > 2)
        reject("E46 version must be q/p/z");
    if (payload.size() > (82 - hrp.size()) * 5 / 8)
        reject("E46 payload exceeds Bech32m capacity");
    std::vector<std::uint8_t> words{version};
    std::uint32_t acc = 0;
    unsigned bits = 0;
    for (auto byte : payload)
    {
        acc = ((acc << 8) | byte) & 0xfff;
        bits += 8;
        while (bits >= 5)
        {
            bits -= 5;
            words.push_back(static_cast<std::uint8_t>((acc >> bits) & 31));
        }
    }
    if (bits)
        words.push_back(static_cast<std::uint8_t>((acc << (5 - bits)) & 31));
    return encode_raw(hrp, words);
}

Decoded decode_e46 (std::string_view encoded, std::string_view expected_hrp)
{
    const auto expected = checked_hrp(expected_hrp);
    require_e46_prefix(expected);
    const auto raw = decode_raw(encoded);
    if (raw.hrp != expected)
        reject("Wrong E46 network or object prefix");
    if (raw.words.empty() || raw.words.front() > 2)
        reject("Missing or unsupported E46 version");
    Decoded out{raw.hrp, raw.words.front(), {}};
    std::uint32_t acc = 0;
    unsigned bits = 0;
    for (std::size_t j = 1; j < raw.words.size(); ++j)
    {
        acc = ((acc << 5) | raw.words[j]) & 0xfff;
        bits += 5;
        if (bits >= 8)
        {
            bits -= 8;
            out.payload.push_back(static_cast<std::uint8_t>((acc >> bits) & 255));
        }
    }
    if (bits >= 5 || ((acc << (8 - bits)) & 255) != 0)
        reject("Non-canonical E46 payload padding");
    return out;
}
} // namespace e46::bech32m
