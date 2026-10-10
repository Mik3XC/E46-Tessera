#include "e46/genesis.hpp"
#include "e46/addresses.hpp"
#include "e46/merkle.hpp"
#include <algorithm>
#include <atomic>
#include <array>
#include <stdexcept>
#include <thread>

namespace e46::genesis
{
namespace
{
Block assemble (shake::Bytes psz_timestamp, std::uint64_t time,
                std::uint32_t bits, std::uint64_t nonce, std::size_t split_at)
{
    if (psz_timestamp.empty() || psz_timestamp.size() > 160 ||
        (split_at == 0 && psz_timestamp.size() > 80) ||
        (split_at != 0 && (split_at > 80 || split_at >= psz_timestamp.size() ||
                           psz_timestamp.size() - split_at > 80)))
        throw std::invalid_argument("pszTimestamp must fit one or two Data outputs of at most 80 bytes");
    (void)chain::compact_to_target(bits);

    const std::array<Digest, 1> zero_coinbase_wtxid{Digest{}};
    const auto commitment = transaction::witness_commitment(zero_coinbase_wtxid);

    transaction::Transaction coinbase{};
    coinbase.version = 1;
    coinbase.inputs.push_back({Digest{}, 0xffffffffU, 0xffffffffU});
    const auto split = split_at == 0 ? psz_timestamp.size() : split_at;
    coinbase.outputs.push_back({0, 0x03, std::vector<std::uint8_t>(
                                psz_timestamp.begin(), psz_timestamp.begin() + split)});
    if (split_at != 0)
        coinbase.outputs.push_back({0, 0x03, std::vector<std::uint8_t>(
                                    psz_timestamp.begin() + split, psz_timestamp.end())});
    coinbase.outputs.push_back({0, 0x03, std::vector<std::uint8_t>(
                                commitment.begin(), commitment.end())});
    coinbase.lock_time = 0;
    coinbase.witnesses.emplace_back(transaction::CoinbaseWitness{
        std::vector<std::uint8_t>(8, 0)});
    transaction::validate_coinbase(coinbase, 0);

    Block result{};
    result.coinbase = std::move(coinbase);
    result.serialized_coinbase = transaction::serialize(result.coinbase);
    result.coinbase_txid = transaction::txid(result.coinbase);
    result.coinbase_wtxid = transaction::wtxid(result.coinbase);
    result.witness_commitment = commitment;

    const std::array<Digest, 1> txids{result.coinbase_txid};
    result.header.version = 1;
    result.header.prev_block = {};
    result.header.merkle_root = merkle::merkle_root(txids);
    result.header.event_root = {};
    result.header.time = time;
    result.header.bits = bits;
    result.header.nonce = nonce;
    result.serialized_header = chain::serialize_header(result.header);
    result.block_id = addresses::block_id(result.serialized_header);
    result.pow_valid = chain::check_header_pow(result.header);
    return result;
}
} // namespace

Block build (shake::Bytes psz_timestamp, std::uint64_t time,
             std::uint32_t bits, std::uint64_t nonce, std::size_t split_at)
{
    return assemble(psz_timestamp, time, bits, nonce, split_at);
}

Block mine (shake::Bytes psz_timestamp, std::uint64_t time,
            std::uint32_t bits, std::uint32_t workers, std::uint64_t max_nonce,
            std::size_t split_at)
{
    if (workers == 0 || workers > 4)
        throw std::invalid_argument("Genesis miner supports 1..4 workers");
    auto candidate = assemble(psz_timestamp, time, bits, 0, split_at);
    if (candidate.pow_valid)
        return candidate;
    const auto target = chain::compact_to_target(bits);

    std::atomic<std::uint64_t> best_nonce{0};
    std::atomic<bool> found{false};
    std::vector<std::thread> threads;
    threads.reserve(workers);
    for (std::uint32_t worker = 0; worker < workers; ++worker)
    {
        threads.emplace_back([&, worker] {
            auto header = candidate.header;
            std::uint64_t nonce = worker;
            while (nonce <= max_nonce)
            {
                if (found.load(std::memory_order_acquire) &&
                    nonce > best_nonce.load(std::memory_order_relaxed))
                    break;
                header.nonce = nonce;
                const auto raw = chain::serialize_header(header);
                if (rl::rl_v3_header_pow(raw, target))
                {
                    auto current = best_nonce.load(std::memory_order_relaxed);
                    while ((!found.load(std::memory_order_relaxed) || nonce < current) &&
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
        throw std::runtime_error("No valid genesis nonce in the requested range");
    return assemble(psz_timestamp, time, bits, best_nonce.load(std::memory_order_relaxed), split_at);
}
} // namespace e46::genesis
