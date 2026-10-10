#include "e46/block_qtl.hpp"
#include "e46/rad.hpp"
#include "e46/shake.hpp"
#include <algorithm>
#include <atomic>
#include <limits>
#include <stdexcept>
#include <thread>
#include <vector>

namespace e46::block_qtl
{
namespace
{
void write_u64_le (std::uint8_t *out, std::uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i)
        out[i] = static_cast<std::uint8_t>(value >> (i * 8));
}

bool common_salt (const transaction::Transaction &tx, Salt &salt)
{
    if (tx.inputs.empty() || tx.witnesses.size() != tx.inputs.size())
        return false;
    bool found = false;
    for (const auto &witness : tx.witnesses)
    {
        if (const auto *qtl = std::get_if<transaction::BlockQtlWitness>(&witness))
        {
            if (!found)
            {
                salt = qtl->salt;
                found = true;
            }
            else if (salt != qtl->salt)
            {
                return false;
            }
        }
    }
    return found;
}

Commitment make_commitment_with_salt (const transaction::Transaction &tx,
                                      const Salt &salt)
{
    const auto base = transaction::serialize_without_witnesses(tx);
    const auto full = transaction::serialize(tx);
    if (full.size() < base.size())
        throw std::logic_error("Full transaction is shorter than its base encoding");
    const auto witnesses = shake::shake256_256(
        shake::Bytes{full.data() + base.size(), full.size() - base.size()});
    const auto txid = transaction::txid(tx);
    auto hasher = shake::Shake256::tagged("E46-commit");
    hasher.update(txid);
    hasher.update(witnesses);
    hasher.update(salt);
    const auto digest = hasher.finalize(32);
    Commitment commitment{};
    std::copy(digest.begin(), digest.end(), commitment.begin());
    return commitment;
}
} // namespace

Commitment make_commitment (const transaction::Transaction &tx)
{
    Salt salt{};
    if (!common_salt(tx, salt))
        throw std::invalid_argument("Block QTL inputs must share one 32-byte salt");
    return make_commitment_with_salt(tx, salt);
}

Commitment make_commitment (const transaction::Transaction &tx, const Salt &salt)
{
    Salt witness_salt{};
    if (!common_salt(tx, witness_salt) || witness_salt != salt)
        throw std::invalid_argument("Commitment salt must match every Block QTL input witness");
    return make_commitment_with_salt(tx, salt);
}

merkle::Event make_event (const Commitment &commitment, std::uint64_t nonce)
{
    std::vector<std::uint8_t> body(commitment.begin(), commitment.end());
    const auto offset = body.size();
    body.resize(offset + 8);
    write_u64_le(body.data() + offset, nonce);
    return {event_type, {commitment.begin(), commitment.end()}, std::move(body)};
}

bool verify_event (const merkle::Event &event, unsigned minimum_z)
{
    if (minimum_z > 128 || event.type != event_type || event.id.size() != 32 ||
        event.body.size() != 40 ||
        !std::equal(event.id.begin(), event.id.end(), event.body.begin()))
        return false;
    Commitment commitment{};
    std::copy_n(event.body.begin(), commitment.size(), commitment.begin());
    std::uint64_t nonce = 0;
    for (unsigned i = 0; i < 8; ++i)
        nonce |= static_cast<std::uint64_t>(event.body[32 + i]) << (i * 8);
    return rad::commit_valid(commitment, nonce, minimum_z);
}

void validate_block_events (std::span<const merkle::Event> events,
                            unsigned minimum_z)
{
    if (minimum_z > 128)
        throw std::invalid_argument("Z_commit must be in 0..128");
    const auto ordered = merkle::sorted_events(events);
    const auto qtl_count = static_cast<std::size_t>(std::count_if(ordered.begin(), ordered.end(), [] (const auto &event) {
        return event.type == event_type;
    }));
    if (qtl_count > max_commitments_per_block)
        throw std::invalid_argument("Block exceeds the 1,000 Block QTL commitment limit");
    for (const auto &event : ordered)
    {
        if (event.type == event_type && !verify_event(event, minimum_z))
            throw std::invalid_argument("Invalid Block QTL commitment event");
    }
}

merkle::Event mine_event (const transaction::Transaction &tx,
                          unsigned minimum_z,
                          std::uint32_t workers,
                          std::uint64_t max_nonce)
{
    if (minimum_z > 128)
        throw std::invalid_argument("Z_commit must be in 0..128");
    if (workers == 0 || workers > 4)
        throw std::invalid_argument("Block QTL miner supports 1..4 workers");
    const auto commitment = make_commitment(tx);
    if (rad::commit_valid(commitment, 0, minimum_z))
        return make_event(commitment, 0);

    std::atomic<std::uint64_t> best_nonce{UINT64_MAX};
    std::atomic<bool> found{false};
    std::vector<std::thread> threads;
    threads.reserve(workers);
    for (std::uint32_t worker = 0; worker < workers; ++worker)
    {
        threads.emplace_back([&, worker] {
            std::uint64_t nonce = worker;
            while (nonce <= max_nonce)
            {
                if (found.load(std::memory_order_acquire) &&
                    nonce > best_nonce.load(std::memory_order_relaxed))
                    break;
                if (rad::commit_valid(commitment, nonce, minimum_z))
                {
                    auto current = best_nonce.load(std::memory_order_relaxed);
                    while (nonce < current &&
                           !best_nonce.compare_exchange_weak(current, nonce,
                               std::memory_order_relaxed, std::memory_order_relaxed))
                    {
                    }
                    found.store(true, std::memory_order_release);
                }
                if (workers > max_nonce - nonce || nonce > UINT64_MAX - workers)
                    break;
                nonce += workers;
            }
        });
    }
    for (auto &thread : threads)
        thread.join();
    if (!found.load(std::memory_order_acquire))
        throw std::runtime_error("No Block QTL nonce in the requested range");
    return make_event(commitment, best_nonce.load(std::memory_order_relaxed));
}

bool verify_reveal (const transaction::Transaction &tx,
                    const merkle::Event &event,
                    std::uint64_t depth,
                    unsigned minimum_z)
{
    if (depth < min_reveal_depth || depth > max_reveal_depth ||
        !verify_event(event, minimum_z))
        return false;
    Commitment commitment{};
    if (event.body.size() != 40)
        return false;
    std::copy_n(event.body.begin(), commitment.size(), commitment.begin());
    try
    {
        return make_commitment(tx) == commitment;
    }
    catch (const std::invalid_argument &)
    {
        return false;
    }
}
} // namespace e46::block_qtl
