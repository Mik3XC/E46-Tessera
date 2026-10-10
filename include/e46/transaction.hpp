#pragma once

#include "e46/shake.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <variant>
#include <vector>

namespace e46::transaction
{
using Bytes = shake::Bytes;
using Digest = shake::Digest256;
inline constexpr std::uint64_t max_amount = 4'600'000'000'000'000ULL;
inline constexpr std::uint64_t coinbase_maturity = 100;

struct Input
{
    Digest previous_txid{};
    std::uint32_t previous_index{};
    std::uint32_t sequence{};
    bool operator== (const Input &) const = default;
};

struct Output
{
    std::uint64_t value{};
    std::uint8_t type{};
    std::vector<std::uint8_t> payload;
    bool operator== (const Output &) const = default;
};

struct CoinbaseWitness
{
    std::vector<std::uint8_t> coinbase_data; // extranonce[8] || 0..100 free bytes
    bool operator== (const CoinbaseWitness &) const = default;
};

struct SingleOwnerWitness
{
    std::array<std::uint8_t, 32> public_key{};
    std::vector<std::uint8_t> signature;
    bool operator== (const SingleOwnerWitness &) const = default;
};

struct SharedWitness
{
    std::uint8_t threshold{};
    std::vector<std::array<std::uint8_t, 32>> public_keys;
    std::vector<std::vector<std::uint8_t>> signatures; // empty for non-signers
    bool operator== (const SharedWitness &) const = default;
};

struct BlockQtlWitness
{
    std::array<std::uint8_t, 32> public_key{};
    std::vector<std::uint8_t> signature;
    std::array<std::uint8_t, 32> salt{};
    bool operator== (const BlockQtlWitness &) const = default;
};

using Witness = std::variant<CoinbaseWitness, SingleOwnerWitness, SharedWitness,
                             BlockQtlWitness>;

struct Transaction
{
    std::uint32_t version{};
    std::vector<Input> inputs;
    std::vector<Output> outputs;
    std::uint64_t lock_time{};
    std::vector<Witness> witnesses; // one per input
    bool operator== (const Transaction &) const = default;
};

struct SpentCoin
{
    Output output;
    bool is_coinbase{};
    std::uint64_t creation_height{};
};

bool is_coinbase (const Transaction &tx) noexcept;
bool is_standard (const Transaction &tx) noexcept;
void validate_output (const Output &output);

// Both serializers produce the unique §2g representation. The no-witness
// form is the transaction body through lock_time; the full form appends the
// one typed witness for each input in input order.
std::vector<std::uint8_t> serialize_without_witnesses (const Transaction &tx);
std::vector<std::uint8_t> serialize (const Transaction &tx);
Transaction deserialize (Bytes bytes, std::span<const SpentCoin> spent_coins = {});

Digest txid (const Transaction &tx);
Digest wtxid (const Transaction &tx);
Digest sighash (const Transaction &tx, std::uint32_t input_index,
                std::span<const SpentCoin> spent_coins);

// The first wtxid is replaced by zero before the bound transaction Merkle root
// is computed. The coinbase Data output payload is exactly this 32-byte root.
Digest witness_commitment (std::span<const Digest> wtxids);
bool has_witness_commitment (const Transaction &coinbase, const Digest &commitment);

void validate_coinbase (const Transaction &tx, std::uint64_t block_height);
void validate_transaction (const Transaction &tx, std::span<const SpentCoin> spent_coins,
                           std::uint64_t spending_height);

// CompactSize is public for boundary tests and fixture generation.
std::vector<std::uint8_t> encode_compact_size (std::uint64_t value);
} // namespace e46::transaction
