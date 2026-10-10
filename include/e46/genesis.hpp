#pragma once

#include "e46/header.hpp"
#include "e46/transaction.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace e46::genesis
{
using Digest = shake::Digest256;

struct Block
{
    transaction::Transaction coinbase;
    std::vector<std::uint8_t> serialized_coinbase;
    Digest coinbase_txid{};
    Digest coinbase_wtxid{};
    Digest witness_commitment{};
    chain::Header header;
    std::array<std::uint8_t, 120> serialized_header{};
    Digest block_id{};
    bool pow_valid{};
};

// Builds the unique genesis coinbase and 120-byte header fields. A zero
// split_at puts the whole timestamp in one Data output; otherwise split_at is
// its byte boundary across two outputs. Version 1, zero prev_block/event_root,
// and the §2d proof-of-work limit are used unless explicit values are supplied.
Block build (shake::Bytes psz_timestamp, std::uint64_t time,
             std::uint32_t bits = chain::max_target_bits, std::uint64_t nonce = 0,
             std::size_t split_at = 0);

// Searches nonce values from zero and returns the lowest valid nonce. Workers
// are capped at four; max_nonce is inclusive and exists for bounded tests.
Block mine (shake::Bytes psz_timestamp, std::uint64_t time,
            std::uint32_t bits = chain::max_target_bits, std::uint32_t workers = 4,
            std::uint64_t max_nonce = UINT64_MAX, std::size_t split_at = 0);
} // namespace e46::genesis
