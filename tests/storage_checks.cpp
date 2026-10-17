#include "e46/node.hpp"
#include "e46/header.hpp"
#include "e46/addresses.hpp"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <thread>

namespace n = e46::node;
namespace tx = e46::transaction;
using Bytes = std::vector<std::uint8_t>;
using Path = std::filesystem::path;

void require(bool ok, const std::string &message)
{
    if (!ok) throw std::runtime_error(message);
}
Bytes read(const Path &path)
{
    std::ifstream in(path, std::ios::binary);
    require(bool(in), "Cannot read fixture " + path.string());
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}
void write(const Path &path, const Bytes &bytes)
{
    if (std::filesystem::exists(path)) { require(read(path) == bytes, "Fixture differs"); return; }
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    require(bool(out), "Cannot write fixture");
}
Bytes height_record(const Path &chain, unsigned height)
{
    for (const auto &entry : std::filesystem::directory_iterator(chain / "blocks"))
        if (entry.path().extension() == ".blk" && std::stoull(entry.path().filename().string().substr(0, 20)) == height)
            return read(entry.path());
    throw std::runtime_error("Historical block is missing");
}
n::Digest id(const Bytes &raw) { return e46::addresses::block_id(e46::shake::Bytes(raw).subspan(8, 120)); }
n::AddressPayload miner_b() { n::AddressPayload p{}; p.fill(0x42); return p; }
n::AddressPayload miner_a(n::Node &node)
{
    n::AddressPayload p{};
    const auto payload = node.get_block(std::uint64_t{1}).block.transactions.front().outputs.front().payload;
    require(payload.size() == p.size(), "Expected single-owner miner");
    std::copy(payload.begin(), payload.end(), p.begin()); return p;
}
void refresh_roots(n::Block &block)
{
    std::vector<n::Digest> ids, witnesses;
    for (const auto &t : block.transactions) witnesses.push_back(tx::wtxid(t));
    const auto commitment = tx::witness_commitment(witnesses);
    block.transactions.front().outputs.back().payload.assign(commitment.begin(), commitment.end());
    for (const auto &t : block.transactions) ids.push_back(tx::txid(t));
    block.header.merkle_root = e46::merkle::merkle_root(ids);
}
void generate(const Path &root, const Path &chain, unsigned seconds)
{
    std::filesystem::create_directories(root);
    write(root / "a1.blk", height_record(chain, 1));
    write(root / "a2.blk", height_record(chain, 2));
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    auto solve = [&](const std::string &name, n::Block &block) {
        const auto path = root / name;
        if (std::filesystem::exists(path))
        {
            const auto cached = read(path);
            block.header.nonce = e46::chain::deserialize_header(e46::shake::Bytes(cached).subspan(8, 120)).nonce;
            require(n::encode_record(block) == cached && e46::chain::check_header_pow(block.header), "Bad cached proof of work");
            return;
        }
        std::cout << "Mining " << name << " at unchanged testnet bits " << block.header.bits << std::endl;
        std::stop_source stop;
        std::jthread timer([&](std::stop_token finished) {
            while (!finished.stop_requested() && std::chrono::steady_clock::now() < deadline)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (!finished.stop_requested()) stop.request_stop();
        });
        const auto began = std::chrono::steady_clock::now();
        const bool found = n::Node::solve(block, stop.get_token());
        timer.request_stop(); timer.join();
        require(found, "Mining deadline reached; completed fixtures retained for resume");
        write(path, n::encode_record(block));
        std::cout << "MINED " << name << " nonce " << block.header.nonce << " seconds "
                  << std::chrono::duration<double>(std::chrono::steady_clock::now() - began).count() << std::endl;
    };
    n::Node branch(root / "generator");
    for (unsigned h = 1; h <= 3; ++h)
    {
        const auto name = "b" + std::to_string(h) + ".blk";
        if (branch.height() < h)
        {
            auto block = branch.block_template(miner_b());
            // Use fixed parent-relative times so a partial generation can resume.
            block.header.time = branch.get_block(branch.height()).block.header.time + e46::chain::target_spacing;
            solve(name, block);
            branch.import_record(n::encode_record(block));
        }
        write(root / name, branch.block_record(branch.get_block(std::uint64_t{h}).id));
    }
    auto bad = branch.get_block(std::uint64_t{2}).block;
    tx::Transaction spend{}; spend.version = 1;
    n::Digest missing{}; missing.fill(0x77);
    spend.inputs.push_back({missing, 0, 0xffffffffU});
    spend.outputs.push_back({1, 0x00, Bytes(32, 0x42)});
    spend.witnesses.emplace_back(tx::SingleOwnerWitness{{}, Bytes(7856)});
    bad.transactions.push_back(spend);
    refresh_roots(bad); solve("bad2.blk", bad);
    auto child = branch.get_block(std::uint64_t{3}).block;
    child.header.prev_block = e46::addresses::block_id(e46::chain::serialize_header(bad.header));
    solve("bad3.blk", child);
    std::cout << "ALL REAL-PROOF-OF-WORK FIXTURES READY" << std::endl;
}
std::string capture(n::Node &node, const n::AddressPayload &a)
{
    std::ostringstream out;
    for (std::uint64_t h = 0; h <= node.height(); ++h)
    {
        const auto info = node.get_block(h);
        const auto raw = n::encode_record(info.block);
        out.write(reinterpret_cast<const char *>(raw.data()), static_cast<std::streamsize>(raw.size()));
        // Pools and UTXO descriptors are compared independently of record bytes.
        for (const auto &owner : {a, miner_b()})
        {
            out << node.balance(owner) << ':';
            for (const auto &coin : node.coins(owner))
            {
                out.write(reinterpret_cast<const char *>(coin.txid.data()), coin.txid.size());
                out << coin.index << ':' << coin.coin.output.value << ':' << coin.coin.creation_height << ':'
                    << coin.coin.is_coinbase << ':' << coin.blocks_to_maturity << ':' << coin.pending_spend;
            }
        }
    }
    const auto pools = node.pool_balances();
    out << pools.n_pool << ':' << pools.z_pool;
    for (const auto &txid : node.mempool_txids()) out.write(reinterpret_cast<const char *>(txid.data()), txid.size());
    return out.str();
}
void stats(const n::Node &node)
{
    const auto s = node.storage_stats();
    require(s.undo_records == node.height(), "Undo must exist only for active non-genesis blocks");
    std::cout << "STORAGE tip_coins=" << s.tip_coins << " undo_saved_coins=" << s.undo_saved_coins
              << " total_coin_entries=" << s.tip_coins + s.undo_saved_coins
              << " undo_created_outpoints=" << s.undo_created_outputs << " undo_records=" << s.undo_records
              << " index_entries=" << s.indexed_blocks << " invalid_blocks=" << s.invalid_blocks << std::endl;
}
void exercise(const Path &fixtures, const Path &root)
{
    require(!std::filesystem::exists(root), "Exercise output must be a new directory");
    std::filesystem::create_directories(root);
    const auto a1 = read(fixtures / "a1.blk"), a2 = read(fixtures / "a2.blk");
    const auto b1 = read(fixtures / "b1.blk"), b2 = read(fixtures / "b2.blk"), b3 = read(fixtures / "b3.blk");
    const auto bad2 = read(fixtures / "bad2.blk"), bad3 = read(fixtures / "bad3.blk");
    {
        n::Node node(root / "one"); node.import_record(a1); node.import_record(b1);
        require(node.tip_id() == id(a1), "Equal work must retain the active tip");
        node.import_record(b2); require(node.tip_id() == id(b2), "One-block reorg failed");
        require(node.block_record(id(a1)) == a1, "Abandoned block not preserved");
        stats(node);
    }
    { n::Node node(root / "one"); require(node.tip_id() == id(b2), "Reorg lost after restart"); }
    std::cout << "PASS one-block switch, equal-work stability, abandoned record and restart" << std::endl;
    {
        n::Node node(root / "deep"); node.import_record(a1); node.import_record(a2);
        const auto a = miner_a(node); const auto before = node.balance(a);
        require(before > 0 && node.balance(miner_b()) == 0, "Unexpected initial balances");
        node.import_record(b1); node.import_record(b2);
        require(node.tip_id() == id(a2), "Equal-work deep branch changed tip");
        node.import_record(b3);
        require(node.tip_id() == id(b3) && node.balance(a) == 0 && node.balance(miner_b()) > 0, "Deep reorg balances are wrong");
        std::cout << "BALANCE deep before_A=" << before << " after_A=" << node.balance(a)
                  << " after_B=" << node.balance(miner_b()) << std::endl;
        stats(node);
    }
    { n::Node node(root / "deep"); require(node.tip_id() == id(b3), "Deep reorg lost after restart"); }
    std::cout << "PASS two-block disconnect, three-block connect, balances and restart" << std::endl;
    { n::Node baseline(root / "baseline"); baseline.import_record(a1); baseline.import_record(a2); }
    std::string before;
    n::AddressPayload a{};
    {
        n::Node node(root / "invalid"); node.import_record(a1); node.import_record(a2);
        a = miner_a(node); before = capture(node, a);
        node.import_record(b1); node.import_record(bad2);
        const auto attempts = node.storage_stats().validation_attempts;
        bool rejected = false;
        try { node.import_record(bad3); } catch (const std::invalid_argument &) { rejected = true; }
        require(rejected && node.tip_id() == id(a2) && capture(node, a) == before, "Invalid branch did not roll back exactly");
        require(node.storage_stats().validation_attempts > attempts, "Branch was not attempted");
        require(node.storage_stats().invalid_blocks == 2, "Failed block and descendant were not marked invalid");
        const auto after = node.storage_stats().validation_attempts;
        for (const auto &raw : {bad2, bad3})
        {
            rejected = false;
            try { node.import_record(raw); } catch (const std::invalid_argument &) { rejected = true; }
            require(rejected && node.storage_stats().validation_attempts == after, "Invalid branch was retried");
        }
        stats(node);
    }
    { n::Node node(root / "invalid"); require(capture(node, a) == before, "Rollback changed after restart"); }
    std::cout << "PASS invalid second block rolls back exact state, descendants rejected without retry, restart preserved" << std::endl;
}
int main(int argc, char **argv)
{
    try
    {
        if (argc == 5 && std::string(argv[1]) == "generate") generate(argv[2], argv[3], static_cast<unsigned>(std::stoul(argv[4])));
        else if (argc == 4 && std::string(argv[1]) == "exercise") exercise(argv[2], argv[3]);
        else if (argc == 3 && std::string(argv[1]) == "stats") { n::Node node(argv[2]); stats(node); }
        else throw std::invalid_argument("usage: e46-storage-checks generate FIXTURES CHAIN TIMEOUT_SECONDS | exercise FIXTURES OUTPUT | stats DATADIR");
        return 0;
    }
    catch (const std::exception &error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
