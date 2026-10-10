#pragma once

#include "e46/merkle.hpp"
#include "e46/transaction.hpp"
#include <array>
#include <cstdint>
#include <span>

namespace e46::block_qtl
{
using Commitment = transaction::Digest;
using Salt = std::array<std::uint8_t, 32>;
inline constexpr std::uint8_t event_type = 0x03;
inline constexpr unsigned provisional_z_commit = 18;
inline constexpr std::size_t max_commitments_per_block = 1'000;
inline constexpr std::uint64_t min_reveal_depth = 6;
inline constexpr std::uint64_t max_reveal_depth = 2'016;

// Makes the 32-byte §2f commitment over the canonical transaction witnesses.
// Every Block QTL input must carry the same salt (decision #24).
Commitment make_commitment (const transaction::Transaction &tx);
Commitment make_commitment (const transaction::Transaction &tx, const Salt &salt);

// Event ID is C; body is C || u64 nonce (LE), as specified by §2g.
merkle::Event make_event (const Commitment &commitment, std::uint64_t nonce);
bool verify_event (const merkle::Event &event, unsigned minimum_z);

// Checks Block QTL event shape, stamp work, duplicate event IDs and the 1,000
// commitment cap. Rad event semantics remain the WO-08 caller's responsibility.
void validate_block_events (std::span<const merkle::Event> events,
                            unsigned minimum_z);

// Finds the lowest valid nonce in [0, max_nonce]. Worker count is capped at 4.
merkle::Event mine_event (const transaction::Transaction &tx,
                          unsigned minimum_z,
                          std::uint32_t workers = 4,
                          std::uint64_t max_nonce = UINT64_MAX);

// Checks the event/work, inclusive depth (6..2,016), transaction witness
// shape, common salt, and C match. Caller authenticates the event's inclusion
// and derives depth from the validated chain; transaction/signature/UTXO and
// double-spend checks remain the transaction/block validator's responsibility.
bool verify_reveal (const transaction::Transaction &tx,
                    const merkle::Event &event,
                    std::uint64_t depth,
                    unsigned minimum_z);
} // namespace e46::block_qtl
