#include "e46/addresses.hpp"
#include "e46/bech32m.hpp"
#include <algorithm>
#include <array>
#include <stdexcept>
#include <vector>

namespace e46::addresses
{
namespace
{
std::string_view prefix (std::string_view kind, Network network)
{
    const bool testnet = network == Network::testnet;
    if (!testnet && network != Network::mainnet)
        throw std::invalid_argument("Unknown E46 network");
    if (kind == "single")
        return testnet ? "te46" : "e46";
    if (kind == "shared")
        return testnet ? "tess" : "tes";
    if (kind == "txid")
        return testnet ? "te46tx" : "e46tx";
    if (kind == "block")
        return testnet ? "te46blk" : "e46blk";
    if (kind == "rad")
        return testnet ? "te46rad" : "e46rad";
    throw std::logic_error("Unknown E46 identifier kind");
}

std::string encode (std::string_view kind, Bytes payload, Network network)
{
    return bech32m::encode_e46(prefix(kind, network), 0, payload);
}

std::vector<std::uint8_t> decode (std::string_view kind, std::string_view encoded,
                                  std::size_t payload_size, Network network)
{
    const auto decoded = bech32m::decode_e46(encoded, prefix(kind, network));
    if (decoded.version != 0)
        throw std::invalid_argument("Only E46 version q is active for WO-05 objects");
    if (decoded.payload.size() != payload_size)
        throw std::invalid_argument("E46 payload has the wrong length for this object");
    return decoded.payload;
}

template <std::size_t N> std::array<std::uint8_t, N> as_array (std::vector<std::uint8_t> bytes)
{
    if (bytes.size() != N)
        throw std::logic_error("Internal E46 payload length mismatch");
    std::array<std::uint8_t, N> out{};
    std::copy(bytes.begin(), bytes.end(), out.begin());
    return out;
}
} // namespace

Payload256 single_owner_payload (Bytes public_key)
{
    if (public_key.size() != 32)
        throw std::invalid_argument("SLH-DSA-SHAKE-128s public key must be 32 bytes");
    auto message = std::vector<std::uint8_t>{'E', '4', '6', '-', 'a', 'd', 'd', 'r', 'e', 's', 's', 0};
    message.insert(message.end(), public_key.begin(), public_key.end());
    const auto rl_hash = rl::rl_v3_128(message);
    const auto shake_hash = shake::shake256_tagged("E46-address", public_key, 16);
    Payload256 payload{};
    std::copy(rl_hash.begin(), rl_hash.end(), payload.begin());
    std::copy(shake_hash.begin(), shake_hash.end(), payload.begin() + 16);
    return payload;
}

std::string single_owner_address (Bytes public_key, Network network)
{
    const auto payload = single_owner_payload(public_key);
    return encode("single", payload, network);
}

Payload256 shared_payload (std::uint8_t threshold, std::span<const PublicKey> public_keys)
{
    if (public_keys.empty() || public_keys.size() > 15 || threshold == 0 ||
        threshold > public_keys.size())
        throw std::invalid_argument("Shared address requires 1 <= k <= n <= 15");
    std::vector<PublicKey> sorted(public_keys.begin(), public_keys.end());
    std::sort(sorted.begin(), sorted.end());
    if (std::adjacent_find(sorted.begin(), sorted.end()) != sorted.end())
        throw std::invalid_argument("Shared address public keys must be distinct");
    std::vector<std::uint8_t> message;
    message.reserve(2 + sorted.size() * PublicKey{}.size());
    message.push_back(threshold);
    message.push_back(static_cast<std::uint8_t>(sorted.size()));
    for (const auto &key : sorted)
        message.insert(message.end(), key.begin(), key.end());
    const auto digest = shake::shake256_tagged_256("E46-shared", message);
    return digest;
}

std::string shared_address (std::uint8_t threshold, std::span<const PublicKey> public_keys,
                           Network network)
{
    const auto payload = shared_payload(threshold, public_keys);
    return encode("shared", payload, network);
}

Payload256 decode_single_owner_address (std::string_view address, Network network)
{
    return as_array<32>(decode("single", address, 32, network));
}

Payload256 decode_shared_address (std::string_view address, Network network)
{
    return as_array<32>(decode("shared", address, 32, network));
}

Digest256 txid (Bytes transaction_without_witnesses)
{
    return shake::shake256_tagged_256("E46-txid", transaction_without_witnesses);
}

Digest256 wtxid (Bytes full_transaction)
{
    return shake::shake256_tagged_256("E46-wtxid", full_transaction);
}

Digest256 block_id (Bytes serialized_header)
{
    if (serialized_header.size() != rl::header_bytes)
        throw std::invalid_argument("Serialized E46 header must be exactly 120 bytes");
    return shake::shake256_tagged_256("E46-block", serialized_header);
}

Digest128 rad_id (const shake::Digest256 &previous_block_id, const rad::Rad &event)
{
    return rad::id({previous_block_id, event.window}, event);
}

std::string encode_txid (const Digest256 &id, Network network)
{
    return encode("txid", id, network);
}

std::string encode_block_id (const Digest256 &id, Network network)
{
    return encode("block", id, network);
}

std::string encode_rad_id (const Digest128 &id, Network network)
{
    return encode("rad", id, network);
}

Digest256 decode_txid (std::string_view encoded, Network network)
{
    return as_array<32>(decode("txid", encoded, 32, network));
}

Digest256 decode_block_id (std::string_view encoded, Network network)
{
    return as_array<32>(decode("block", encoded, 32, network));
}

Digest128 decode_rad_id (std::string_view encoded, Network network)
{
    return as_array<16>(decode("rad", encoded, 16, network));
}
} // namespace e46::addresses
