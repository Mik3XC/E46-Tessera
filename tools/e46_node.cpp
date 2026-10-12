#include "e46/addresses.hpp"
#include "e46/node.hpp"
#include "e46/p2p.hpp"
#include <fstream>
#include <sstream>
#include <csignal>
#include "e46/rl.hpp"
#include "e46/transaction.hpp"
#include <algorithm>
#include <bit>
#include <charconv>
#include <cstdint>
#include <filesystem>
#include <fcntl.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <stdexcept>
#include <vector>
#include <sys/file.h>
#include <unistd.h>

namespace
{
// Serialize CLI writers from startup through exit, including the mining loop.
// Read-only commands can still inspect the last published block during mining.
class WriterLock
{
public:
    WriterLock (const std::filesystem::path &directory, bool needed)
    {
        if (!needed) return;
        std::filesystem::create_directories(directory);
        fd_ = ::open((directory / "node-write.lock").c_str(), O_CREAT | O_RDWR, 0600);
        if (fd_ < 0) throw std::runtime_error("Cannot open the node writer lock");
        if (::flock(fd_, LOCK_EX | LOCK_NB) != 0)
        {
            ::close(fd_); fd_ = -1;
            throw std::runtime_error("Another node process is using this datadir (a running daemon or another command). Stop it, or send commands to the running daemon, and try again.");
        }
    }
    ~WriterLock () { if (fd_ >= 0) ::close(fd_); }
    WriterLock (const WriterLock &) = delete;
    WriterLock &operator=(const WriterLock &) = delete;
private:
    int fd_{-1};
};

std::vector<std::uint8_t> unhex (std::string_view value)
{
    if (value.size() % 2 != 0)
        throw std::invalid_argument("hex input must have an even number of characters");
    std::vector<std::uint8_t> result(value.size() / 2);
    auto nibble = [] (char c) -> std::uint8_t {
        if (c >= '0' && c <= '9') return static_cast<std::uint8_t>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<std::uint8_t>(c - 'a' + 10);
        if (c >= 'A' && c <= 'F') return static_cast<std::uint8_t>(c - 'A' + 10);
        throw std::invalid_argument("invalid hex character");
    };
    for (std::size_t i = 0; i < result.size(); ++i)
        result[i] = static_cast<std::uint8_t>((nibble(value[2 * i]) << 4) | nibble(value[2 * i + 1]));
    return result;
}

std::string hex (e46::shake::Bytes bytes)
{
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (const auto byte : bytes)
    {
        result.push_back(digits[byte >> 4]);
        result.push_back(digits[byte & 15]);
    }
    return result;
}

std::uint64_t number (std::string_view value)
{
    std::uint64_t result{};
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size())
        throw std::invalid_argument("expected an unsigned integer");
    return result;
}

e46::shake::Digest256 digest (std::string_view value)
{
    const auto bytes = unhex(value);
    if (bytes.size() != 32)
        throw std::invalid_argument("digest must be exactly 32 bytes of hex");
    e46::shake::Digest256 result{};
    std::copy(bytes.begin(), bytes.end(), result.begin());
    return result;
}

void usage ()
{
    std::cerr << "usage: e46-node [--datadir DIR] <getblock height|id|gettx txid|balance te46-address|submit tx-hex|mempool|template te46-address|mine count te46-address|snapshot [limit]|serve [--listen HOST:PORT] [--connect HOST:PORT] [--max-peers N]|status|stop|stop-mining|import BLOCK.blk|rebuild>\n";
}

template <typename Left, typename Right>
std::uint32_t bit_difference (const Left &left, const Right &right)
{
    std::uint32_t count = 0;
    for (std::size_t i = 0; i < left.size(); ++i)
        count += std::popcount(static_cast<unsigned>(left[i] ^ right[i]));
    return count;
}

void transaction_snapshot (const e46::node::Node &node, const e46::transaction::Transaction &tx)
{
    namespace t = e46::transaction;
    const bool coinbase = t::is_coinbase(tx);
    std::cout << "{\"id\":\"" << hex(t::txid(tx))
              << "\",\"wtxid\":\"" << hex(t::wtxid(tx))
              << "\",\"coinbase\":" << (coinbase ? "true" : "false")
              << ",\"version\":" << tx.version
              << ",\"lockTime\":\"" << tx.lock_time << "\""
              << ",\"inputCount\":" << tx.inputs.size()
              << ",\"outputCount\":" << tx.outputs.size() << ",\"inputs\":[";
    for (std::size_t i = 0; i < tx.inputs.size(); ++i)
    {
        if (i) std::cout << ',';
        const auto &input = tx.inputs[i];
        std::cout << "{\"txid\":\"" << hex(input.previous_txid)
                  << "\",\"index\":" << input.previous_index
                  << ",\"sequence\":" << input.sequence << '}';
    }
    std::cout << "],\"outputs\":[";
    for (std::size_t i = 0; i < tx.outputs.size(); ++i)
    {
        if (i) std::cout << ',';
        const auto &output = tx.outputs[i];
        // Decimal strings preserve exact amounts in browser JSON consumers.
        std::cout << "{\"value\":\"" << output.value << "\",\"type\":"
                  << static_cast<unsigned>(output.type) << ",\"payload\":\""
                  << hex(output.payload) << "\"}";
    }
    std::cout << "],\"witnesses\":[";
    for (std::size_t i = 0; i < tx.witnesses.size(); ++i)
    {
        if (i) std::cout << ',';
        std::visit([&] (const auto &w) {
            using W = std::decay_t<decltype(w)>;
            if constexpr (std::is_same_v<W, t::CoinbaseWitness>)
                std::cout << "{\"type\":\"coinbase\",\"data\":\"" << hex(w.coinbase_data) << "\"}";
            else if constexpr (std::is_same_v<W, t::SharedWitness>)
            {
                std::cout << "{\"type\":\"shared\",\"threshold\":" << static_cast<unsigned>(w.threshold)
                          << ",\"publicKeys\":[";
                for (std::size_t j = 0; j < w.public_keys.size(); ++j)
                    std::cout << (j ? ",\"" : "\"") << hex(w.public_keys[j]) << '"';
                std::cout << "],\"signatureBytes\":[";
                for (std::size_t j = 0; j < w.signatures.size(); ++j)
                    std::cout << (j ? "," : "") << w.signatures[j].size();
                std::cout << "]}";
            }
            else
            {
                std::cout << "{\"type\":\"" << (std::is_same_v<W, t::BlockQtlWitness> ? "Block-QTL" : "single-owner")
                          << "\",\"publicKey\":\"" << hex(w.public_key)
                          << "\",\"signatureBytes\":" << w.signature.size();
                if constexpr (std::is_same_v<W, t::BlockQtlWitness>)
                    std::cout << ",\"salt\":\"" << hex(w.salt) << '"';
                std::cout << '}';
            }
        }, tx.witnesses[i]);
    }
    std::cout << "],\"sighashes\":[";
    if (!coinbase)
    {
        std::vector<t::SpentCoin> spent;
        for (const auto &input : tx.inputs)
        {
            const auto previous = node.get_transaction(input.previous_txid);
            if (!previous || input.previous_index >= previous->outputs.size())
                throw std::runtime_error("Cannot resolve confirmed transaction input for sighash");
            // Sighash binds the spent output, not its creation height/maturity.
            spent.push_back({previous->outputs[input.previous_index], t::is_coinbase(*previous), 0});
        }
        for (std::size_t i = 0; i < tx.inputs.size(); ++i)
            std::cout << (i ? ",\"" : "\"") << hex(t::sighash(tx, static_cast<std::uint32_t>(i), spent)) << '"';
    }
    const auto raw = t::serialize(tx);
    std::cout << "],\"serializedBytes\":" << raw.size()
              << ",\"serialized\":\"" << hex(raw) << "\"}";
}

void snapshot (const e46::node::Node &node, std::uint64_t limit, bool p2p = false)
{
    const auto tip = node.height();
    const auto first = limit > tip ? 0 : tip - limit + 1;
    std::string commitment_id;
    std::uint64_t commitment_height{};
    for (std::uint64_t height = tip;; --height)
    {
        const auto block = node.get_block(height);
        for (const auto &event : block.block.events)
        {
            if (event.type == 0x03)
            {
                commitment_id = hex(event.id);
                commitment_height = height;
                break;
            }
        }
        if (!commitment_id.empty() || height == 0 || tip - height >= 2016) break;
    }
    std::cout << "{\"network\":\"E46-TESTNET\",\"phase\":1,\"radEnabled\":false,"
              << "\"p2pEnabled\":" << (p2p ? "true" : "false") << ",\"height\":" << tip
              << ",\"tipId\":\"" << hex(node.tip_id()) << "\",\"qtl\":";
    if (commitment_id.empty()) std::cout << "null";
    else std::cout << "{\"commitmentId\":\"" << commitment_id
                   << "\",\"height\":" << commitment_height
                   << ",\"depth\":" << tip - commitment_height
                   << ",\"blocksRemaining\":" << (tip - commitment_height >= 6 ? 0 : 6 - (tip - commitment_height))
                   << '}';
    std::cout << ",\"blocks\":[";
    bool comma = false;
    for (std::uint64_t height = tip;; --height)
    {
        const auto info = node.get_block(height);
        const auto header = e46::chain::serialize_header(info.block.header);
        const auto folded = e46::rl::rl_v3_128(header);
        const auto unfolded = e46::rl::rl_v3_unfolded(header);
        if (comma) std::cout << ',';
        comma = true;
        std::cout << "{\"height\":" << height << ",\"hash\":\"" << hex(info.id)
                  << "\",\"powHash\":\"" << hex(folded)
                  << "\",\"prevHash\":\"" << hex(info.block.header.prev_block)
                  << "\",\"timestamp\":" << info.block.header.time
                  << ",\"bits\":" << info.block.header.bits
                  << ",\"nonce\":" << info.block.header.nonce
                  << ",\"txCount\":" << info.block.transactions.size()
                  << ",\"eventCount\":" << info.block.events.size()
                  << ",\"paymentRoot\":\"" << hex(info.block.header.merkle_root)
                  << "\",\"eventRoot\":\"" << hex(info.block.header.event_root)
                  << "\",\"serializedSize\":" << info.serialized_size;
        if (height > 0)
        {
            const auto parent = node.get_block(height - 1);
            const auto parent_header = e46::chain::serialize_header(parent.block.header);
            std::cout << ",\"stateDelta\":" << bit_difference(unfolded, e46::rl::rl_v3_unfolded(parent_header))
                      << ",\"foldWeight\":" << bit_difference(folded, e46::rl::rl_v3_128(parent_header));
        }
        std::cout << ",\"transactions\":[";
        for (std::size_t i = 0; i < info.block.transactions.size(); ++i)
        {
            if (i) std::cout << ',';
            transaction_snapshot(node, info.block.transactions[i]);
        }
        std::cout << "],\"events\":[";
        for (std::size_t i = 0; i < info.block.events.size(); ++i)
        {
            if (i) std::cout << ',';
            const auto &event = info.block.events[i];
            std::cout << "{\"id\":\"" << hex(event.id) << "\",\"type\":\""
                      << (event.type == 0x03 ? "QTL_COMMIT" : event.type == 0x02 ? "RAD" : "UNKNOWN")
                      << "\",\"typeCode\":" << static_cast<unsigned>(event.type) << '}';
        }
        std::cout << "]}";
        if (height == first) break;
    }
    std::cout << "]}\n";
}
} // namespace

int dispatch(e46::node::Node &node, int argc, char **argv, bool p2p)
{
    const std::string_view command(argv[3]);
    if (command == "rebuild" && argc == 4)
    {
        std::cout << "REBUILT height " << node.height() << " tip " << hex(node.tip_id()) << '\n';
        return 0;
    }
    if (command == "import" && argc == 5)
    {
        const auto size = std::filesystem::file_size(argv[4]);
        if (size > 4'100'000) throw std::invalid_argument("Block record exceeds size limit");
        std::ifstream stream(argv[4], std::ios::binary);
        std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
        if (!stream.read(reinterpret_cast<char *>(bytes.data()), static_cast<std::streamsize>(size)))
            throw std::runtime_error("Cannot read block record");
        const auto info = node.import_record(bytes);
        std::cout << "IMPORTED " << info.height << ' ' << hex(info.id) << '\n';
        return 0;
    }
        if (command == "mempool" && argc == 4)
        {
            const auto pending = node.mempool_txids();
            std::cout << "transactions " << pending.size() << '\n';
            for (const auto &txid : pending) std::cout << "txid " << hex(txid) << '\n';
            return 0;
        }
        if (command == "template" && argc == 5)
        {
            const auto miner = e46::addresses::decode_single_owner_address(argv[4], e46::addresses::Network::testnet);
            const auto block = node.block_template(miner);
            std::cout << "height " << node.height() + 1 << "\ntransactions " << block.transactions.size()
                      << "\nevents " << block.events.size() << "\nproof_of_work NOT_MINED\n";
            for (const auto &tx : block.transactions)
                std::cout << (e46::transaction::is_coinbase(tx) ? "coinbase " : "txid ")
                          << hex(e46::transaction::txid(tx)) << '\n';
            return 0;
        }
        if (command == "snapshot" && (argc == 4 || argc == 5))
        {
            snapshot(node, argc == 5 ? std::clamp(number(argv[4]), std::uint64_t{1}, std::uint64_t{64}) : 10, p2p);
            return 0;
        }
        if (command == "getblock" && argc == 5)
        {
            const std::string_view key(argv[4]);
            e46::node::BlockInfo info{};
            const bool decimal = !key.empty() && std::all_of(key.begin(), key.end(), [] (char c) {
                return c >= '0' && c <= '9';
            });
            if (decimal)
                info = node.get_block(number(key));
            else if (key.size() == 64)
                info = node.get_block(digest(key));
            else
                info = node.get_block(e46::addresses::decode_block_id(key, e46::addresses::Network::testnet));
            std::cout << "height " << info.height << "\nid " << hex(info.id)
                      << "\nprev " << hex(info.block.header.prev_block)
                      << "\nbits " << info.block.header.bits
                      << "\ntime " << info.block.header.time
                      << "\nmerkle_root " << hex(info.block.header.merkle_root)
                      << "\nevent_root " << hex(info.block.header.event_root)
                      << "\ntransactions " << info.block.transactions.size()
                      << "\nevents " << info.block.events.size()
                      << "\nserialized_size " << info.serialized_size << '\n';
            for (const auto &tx : info.block.transactions)
                std::cout << "txid " << hex(e46::transaction::txid(tx)) << '\n';
            return 0;
        }
        if (command == "gettx" && argc == 5)
        {
            const std::string_view key(argv[4]);
            const auto txid = key.size() == 64 ? digest(key)
                : e46::addresses::decode_txid(key, e46::addresses::Network::testnet);
            const auto tx = node.get_transaction(txid);
            if (!tx)
                throw std::out_of_range("transaction not found");
            std::cout << "txid " << hex(e46::transaction::txid(*tx)) << "\nwtxid "
                      << hex(e46::transaction::wtxid(*tx)) << "\nraw "
                      << hex(e46::transaction::serialize(*tx)) << '\n';
            return 0;
        }
        if (command == "balance" && argc == 5)
        {
            const auto address = e46::addresses::decode_single_owner_address(argv[4], e46::addresses::Network::testnet);
            std::cout << node.balance(address) << '\n';
            return 0;
        }
        if (command == "submit" && argc == 5)
        {
            const auto raw = unhex(argv[4]);
            std::cout << node.submit(raw) << '\n';
            return 0;
        }
        if (command == "mine" && argc == 6)
        {
            const auto count = number(argv[4]);
            const auto address = e46::addresses::decode_single_owner_address(argv[5], e46::addresses::Network::testnet);
            for (const auto &block : node.mine(count, address))
                std::cout << block.height << ' ' << hex(block.id) << '\n';
            return 0;
        }
    throw std::invalid_argument("Unknown command or argument count; run --help");
}

int main(int argc, char **argv)
{
    std::signal(SIGPIPE, SIG_IGN);
    try
    {
        std::filesystem::path directory;
        int first = 1;
        if (argc > 1 && std::string_view(argv[1]) == "--datadir")
        {
            if (argc < 4) { usage(); return 2; }
            directory = argv[2]; first = 3;
        }
        else directory = e46::node::default_data_directory();
        if (first >= argc || std::string_view(argv[first]) == "--help") { usage(); return first >= argc ? 2 : 0; }
        directory = std::filesystem::absolute(directory).lexically_normal();
        std::vector<std::string> args;
        for (int i = first; i < argc; ++i) args.emplace_back(argv[i]);
        if (args[0] != "serve" && args[0] != "rebuild")
            if (const auto answer = e46::p2p::request(directory, args)) { std::cout << *answer; return 0; }
        if (args[0] == "status" || args[0] == "stop" || args[0] == "stop-mining")
            throw std::runtime_error("No daemon running in this datadir");
        // Even a read-only cold start can initialize genesis/recover state.
        WriterLock writer(directory, true);
        if (args[0] == "rebuild" && !std::filesystem::is_directory(directory / "blocks"))
            throw std::runtime_error("No block store to rebuild; use serve to synchronize a fresh datadir");
        e46::node::Node node(directory);
        const auto execute = [&](const std::vector<std::string> &command) {
            std::vector<std::string> values{"e46-node", "--datadir", directory.string()};
            values.insert(values.end(), command.begin(), command.end());
            std::vector<char *> pointers;
            for (auto &value : values) pointers.push_back(value.data());
            std::ostringstream output;
            auto *previous = std::cout.rdbuf(output.rdbuf());
            try { dispatch(node, static_cast<int>(pointers.size()), pointers.data(), args[0] == "serve"); }
            catch (...) { std::cout.rdbuf(previous); throw; }
            std::cout.rdbuf(previous);
            return output.str();
        };
        if (args[0] == "serve")
        {
            e46::p2p::Options options;
            for (std::size_t i = 1; i < args.size(); i += 2)
            {
                if (i + 1 >= args.size()) throw std::invalid_argument("Missing serve option value");
                if (args[i] == "--listen") options.listen = args[i + 1];
                else if (args[i] == "--connect") options.connect.push_back(args[i + 1]);
                else if (args[i] == "--max-peers") options.max_peers = number(args[i + 1]);
                else throw std::invalid_argument("Unknown serve option");
            }
            e46::p2p::serve(node, directory, options, execute);
        }
        else std::cout << execute(args);
        return 0;
    }
    catch (const std::exception &error) { std::cerr << "ERR " << error.what() << '\n'; return 1; }
}
