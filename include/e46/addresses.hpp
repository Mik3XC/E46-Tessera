#pragma once
#include "e46/rad.hpp"
#include "e46/shake.hpp"
#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

// WO-05 address payloads and identifier hashes. This layer consumes canonical
// serialized transaction/header bytes; transaction serialization is WO-12/06.
namespace e46::addresses
{
using Bytes = shake::Bytes;
using Digest256 = shake::Digest256;
using Digest128 = rl::Digest128;
using PublicKey = std::array<std::uint8_t, 32>;
using Payload256 = std::array<std::uint8_t, 32>;
enum class Network
{
    mainnet,
    testnet
};

Payload256 single_owner_payload (Bytes public_key);
std::string single_owner_address (Bytes public_key, Network network);
Payload256 shared_payload (std::uint8_t threshold, std::span<const PublicKey> public_keys);
std::string shared_address (std::uint8_t threshold, std::span<const PublicKey> public_keys,
                            Network network);
Payload256 decode_single_owner_address (std::string_view address, Network network);
Payload256 decode_shared_address (std::string_view address, Network network);

// The spans are the exact byte strings defined in CHAIN-DESIGN §2g.
Digest256 txid (Bytes transaction_without_witnesses);
Digest256 wtxid (Bytes full_transaction); // raw 32-byte digest; never Bech32m encoded
Digest256 block_id (Bytes serialized_header); // exactly 120 bytes
Digest128 rad_id (const shake::Digest256 &previous_block_id, const rad::Rad &event);

std::string encode_txid (const Digest256 &id, Network network);
std::string encode_block_id (const Digest256 &id, Network network);
std::string encode_rad_id (const Digest128 &id, Network network);
Digest256 decode_txid (std::string_view encoded, Network network);
Digest256 decode_block_id (std::string_view encoded, Network network);
Digest128 decode_rad_id (std::string_view encoded, Network network);
} // namespace e46::addresses
