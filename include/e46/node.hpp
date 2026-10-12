#pragma once

#include "e46/emission.hpp"
#include "e46/addresses.hpp"
#include "e46/header.hpp"
#include "e46/merkle.hpp"
#include "e46/transaction.hpp"
#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <vector>

namespace e46::node
{
using Digest = shake::Digest256;
using AddressPayload = addresses::Payload256;

struct Block
{
    chain::Header header;
    std::vector<transaction::Transaction> transactions;
    std::vector<merkle::Event> events;
};

struct BlockInfo
{
    Block block;
    Digest id{};
    std::uint64_t height{};
    emission::PoolBalances pools{};
    std::size_t serialized_size{};
};

class Node
{
public:
    explicit Node (std::filesystem::path data_directory);
    ~Node ();
    Node (Node &&) noexcept;
    Node &operator=(Node &&) noexcept;
    Node (const Node &) = delete;
    Node &operator=(const Node &) = delete;

    std::uint64_t height () const;
    Digest tip_id () const;
    emission::PoolBalances pool_balances () const;
    std::uint64_t balance (const AddressPayload &address) const;
    BlockInfo get_block (std::uint64_t height) const;
    BlockInfo get_block (const Digest &id) const;
    std::optional<transaction::Transaction> get_transaction (const Digest &txid) const;

    // Submit and persist a canonical serialized signed transaction. Block QTL spends are
    // committed automatically and held until the required depth is reached.
    std::string submit (shake::Bytes serialized_transaction);
    std::vector<Digest> mempool_txids () const;
    // Peer admission never starts QTL puzzle mining on behalf of an untrusted peer.
    std::string submit_relay (shake::Bytes raw, const Digest &expected_id);
    bool has_block (const Digest &id) const;
    std::vector<Digest> locator (std::optional<Digest> cursor = {}) const;
    std::optional<Digest> next_after (std::span<const Digest> locator) const;
    std::vector<std::uint8_t> block_record (const Digest &id) const;
    BlockInfo import_record (shake::Bytes raw);
    // Independent header work; no shared Node state is accessed by the miner.
    static bool solve (Block &block, std::stop_token stop);

    // Preview the next candidate without searching for proof of work or storing a block.
    Block block_template (const AddressPayload &miner) const;

    // Mine on the active tip. workers must be in 1..4. The production CLI uses
    // the frozen testnet target; callers supply a test-time only for deterministic
    // validation and fork tests.
    std::vector<BlockInfo> mine (std::uint64_t count, const AddressPayload &miner,
                                 std::uint32_t workers = 4);
    BlockInfo mine_on (const Digest &parent, const AddressPayload &miner,
                       std::uint32_t workers = 4,
                       std::optional<std::uint64_t> time = std::nullopt);

    // Used by malformed-block tests and local block import. Invalid blocks throw.
    BlockInfo accept (const Block &block, std::uint64_t adjusted_time);

private:
    struct Impl;
    Impl *impl_;
};

std::vector<std::uint8_t> encode_record (const Block &block);
std::filesystem::path default_data_directory ();
std::vector<std::uint8_t> serialize_block (const Block &block);
} // namespace e46::node
