#pragma once
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// WO-04: generic BIP-350 framing and E46 q/p/z envelopes.
// No hashing, key validation, address derivation or Bitcoin SegWit policy.
namespace e46::bech32m
{
using Bytes = std::span<const std::uint8_t>;
struct RawDecoded
{
    std::string hrp;
    std::vector<std::uint8_t> words; // five-bit data, checksum removed
};
struct Decoded
{
    std::string hrp;
    std::uint8_t version;
    std::vector<std::uint8_t> payload;
};

// Lowercase canonical output. Uniform uppercase input is accepted and
// normalized; mixed case, bad characters/checksum and >90 characters reject.
// Raw data can be empty. Every word must fit five bits. Invalid input throws
// std::invalid_argument. No input is silently corrected.
std::string encode_raw (std::string_view hrp, Bytes words);
RawDecoded decode_raw (std::string_view encoded);

// Allowed HRPs: e46/te46, tes/tess, e46tx/te46tx, e46blk/te46blk,
// e46rad/te46rad. Version symbols: q=0, p=1, z=2. All use Bech32m.
// Expected HRP is mandatory: validates both object kind and network.
// Reject excess/nonzero padding. Payload meaning, length policy and reserved
// version activation are WO-05, not this framing codec. Empty payload is
// representable, but is not thereby a valid address or transaction identifier.
std::string encode_e46 (std::string_view hrp, std::uint8_t version, Bytes payload);
Decoded decode_e46 (std::string_view encoded, std::string_view expected_hrp);
} // namespace e46::bech32m
