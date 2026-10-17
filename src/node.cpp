#include <cstdlib>
#include "e46/node.hpp"
#include "e46/checkpoints.hpp"
#include "e46/addresses.hpp"
#include "e46/block_qtl.hpp"
#include "e46/genesis.hpp"
#include "e46/rad.hpp"
#include "e46/rl.hpp"
#include "e46/shake.hpp"
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cerrno>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <unistd.h>

namespace e46::node
{
namespace
{
using Bytes = shake::Bytes;
using Work = std::array<std::uint64_t, 5>; // little-endian, enough for u64 height × 257-bit work
using Commitment = block_qtl::Commitment;
constexpr std::array<std::uint8_t, 8> store_magic{'E','4','6','N','D','B','0','1'};
constexpr std::uint64_t disk_floor_bytes = 1ULL << 30;

struct OutPoint
{
    Digest txid{};
    std::uint32_t index{};
    bool operator< (const OutPoint &other) const noexcept
    {
        return txid < other.txid || (txid == other.txid && index < other.index);
    }
};

using UtxoSet = std::map<OutPoint, transaction::SpentCoin>;

struct CommitAtHeight
{
    merkle::Event event;
    std::uint64_t height{};
};

struct State
{
    State () = default;
    State (const State &) = delete;
    State &operator= (const State &) = delete;
    UtxoSet utxos;
    emission::PoolBalances pools;
    std::vector<std::uint64_t> recent_times;
    std::map<Commitment, std::vector<CommitAtHeight>> commitments;
};

// Only changes made by one active block; never a snapshot of its parent.
struct Undo
{
    std::map<OutPoint, std::optional<transaction::SpentCoin>> coins;
    emission::PoolBalances pools;
    std::vector<std::uint64_t> recent_times;
    std::vector<Commitment> commitments;
};

struct IndexEntry
{
    chain::Header header;
    std::vector<std::uint8_t> raw;
    Digest id{};
    Digest parent{};
    std::uint64_t height{};
    Work chainwork{};
    emission::PoolBalances pools{};
    std::size_t size{};
    bool validated{};
    bool invalid{};
};

bool is_zero (const Digest &digest) noexcept
{
    return std::all_of(digest.begin(), digest.end(), [] (std::uint8_t b) { return b == 0; });
}

void write_compact (std::vector<std::uint8_t> &out, std::uint64_t value)
{
    const auto encoded = transaction::encode_compact_size(value);
    out.insert(out.end(), encoded.begin(), encoded.end());
}

void write_varbytes (std::vector<std::uint8_t> &out, Bytes value)
{
    write_compact(out, value.size());
    out.insert(out.end(), value.begin(), value.end());
}

class Reader
{
public:
    explicit Reader (Bytes bytes) : bytes_(bytes) {}

    std::size_t remaining () const noexcept { return bytes_.size() - pos_; }
    bool empty () const noexcept { return pos_ == bytes_.size(); }

    std::uint8_t u8 ()
    {
        require(1);
        return bytes_[pos_++];
    }

    std::uint32_t u32 ()
    {
        std::uint32_t value = 0;
        for (unsigned i = 0; i < 4; ++i)
            value |= static_cast<std::uint32_t>(u8()) << (8 * i);
        return value;
    }

    std::uint64_t u64 ()
    {
        std::uint64_t value = 0;
        for (unsigned i = 0; i < 8; ++i)
            value |= static_cast<std::uint64_t>(u8()) << (8 * i);
        return value;
    }

    Bytes bytes (std::size_t count)
    {
        require(count);
        const auto result = bytes_.subspan(pos_, count);
        pos_ += count;
        return result;
    }

    std::uint64_t compact ()
    {
        const auto prefix = u8();
        if (prefix < 0xfd)
            return prefix;
        if (prefix == 0xfd)
        {
            const auto value = static_cast<std::uint64_t>(u8()) |
                               (static_cast<std::uint64_t>(u8()) << 8);
            if (value < 0xfd)
                throw std::invalid_argument("Non-minimal block CompactSize");
            return value;
        }
        if (prefix == 0xfe)
        {
            const auto value = u32();
            if (value <= 0xffff)
                throw std::invalid_argument("Non-minimal block CompactSize");
            return value;
        }
        const auto value = u64();
        if (value <= 0xffffffffULL)
            throw std::invalid_argument("Non-minimal block CompactSize");
        return value;
    }

    Bytes varbytes (std::size_t maximum)
    {
        const auto length = compact();
        if (length > maximum || length > remaining())
            throw std::invalid_argument("Block record varbytes length outside bounds");
        return bytes(static_cast<std::size_t>(length));
    }

    void require (std::size_t count) const
    {
        if (count > remaining())
            throw std::invalid_argument("Truncated block record");
    }

private:
    Bytes bytes_;
    std::size_t pos_{};
};

std::uint32_t read_u32 (Bytes bytes, std::size_t &offset)
{
    if (offset > bytes.size() || bytes.size() - offset < 4)
        throw std::invalid_argument("Truncated transaction base");
    std::uint32_t value = 0;
    for (unsigned i = 0; i < 4; ++i)
        value |= static_cast<std::uint32_t>(bytes[offset++]) << (8 * i);
    return value;
}

std::uint64_t read_compact (Bytes bytes, std::size_t &offset)
{
    if (offset >= bytes.size())
        throw std::invalid_argument("Truncated transaction CompactSize");
    const auto prefix = bytes[offset++];
    if (prefix < 0xfd)
        return prefix;
    std::uint64_t value = 0;
    unsigned count = 0;
    if (prefix == 0xfd)
        count = 2;
    else if (prefix == 0xfe)
        count = 4;
    else
        count = 8;
    if (bytes.size() - offset < count)
        throw std::invalid_argument("Truncated transaction CompactSize value");
    for (unsigned i = 0; i < count; ++i)
        value |= static_cast<std::uint64_t>(bytes[offset++]) << (8 * i);
    if ((count == 2 && value < 0xfd) || (count == 4 && value <= 0xffff) ||
        (count == 8 && value <= 0xffffffffULL))
        throw std::invalid_argument("Non-minimal transaction CompactSize");
    return value;
}

std::vector<OutPoint> transaction_inputs (Bytes bytes)
{
    std::size_t offset = 0;
    (void)read_u32(bytes, offset);
    const auto count = read_compact(bytes, offset);
    if (count == 0 || count > std::numeric_limits<std::uint32_t>::max() ||
        count > (bytes.size() - offset) / 40)
        throw std::invalid_argument("Invalid transaction input count");
    std::vector<OutPoint> inputs;
    inputs.reserve(static_cast<std::size_t>(count));
    for (std::uint64_t i = 0; i < count; ++i)
    {
        if (bytes.size() - offset < 32)
            throw std::invalid_argument("Truncated transaction outpoint");
        OutPoint outpoint{};
        std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset), 32, outpoint.txid.begin());
        offset += 32;
        outpoint.index = read_u32(bytes, offset);
        (void)read_u32(bytes, offset);
        inputs.push_back(outpoint);
    }
    return inputs;
}

struct RecordParts
{
    chain::Header header;
    std::vector<Bytes> transactions;
    std::vector<merkle::Event> events;
};

RecordParts record_parts (Bytes bytes)
{
    if (bytes.size() > 4'100'000)
        throw std::invalid_argument("Block record exceeds transport limit");
    Reader reader(bytes);
    const auto magic = reader.bytes(store_magic.size());
    if (!std::equal(magic.begin(), magic.end(), store_magic.begin()))
        throw std::invalid_argument("Unknown local block store record version");
    RecordParts result{};
    result.header = chain::deserialize_header(reader.bytes(rl::header_bytes));
    const auto count = reader.compact();
    if (count == 0 || count > reader.remaining() / 60)
        throw std::invalid_argument("Invalid transaction count in block record");
    for (std::uint64_t i = 0; i < count; ++i)
        result.transactions.push_back(reader.varbytes(4'000'000));
    const auto events = reader.compact();
    if (events > reader.remaining() / 3)
        throw std::invalid_argument("Invalid event count in block record");
    for (std::uint64_t i = 0; i < events; ++i)
    {
        merkle::Event event{};
        event.type = reader.u8();
        const auto id = reader.varbytes(32), body = reader.varbytes(256);
        event.id.assign(id.begin(), id.end());
        event.body.assign(body.begin(), body.end());
        result.events.push_back(std::move(event));
    }
    if (!reader.empty()) throw std::invalid_argument("Trailing bytes after stored block record");
    return result;
}

// Read a previously validated output directly from the transaction base. Its
// witness does not need decoding to recover the output type for historical reads.
transaction::Output recorded_output (Bytes raw, std::uint32_t index)
{
    Reader reader(raw);
    (void)reader.u32();
    const auto inputs = reader.compact();
    if (inputs > reader.remaining() / 40) throw std::invalid_argument("Invalid stored input count");
    (void)reader.bytes(static_cast<std::size_t>(inputs) * 40);
    const auto count = reader.compact();
    if (index >= count) throw std::invalid_argument("Stored output index out of bounds");
    for (std::uint64_t i = 0; i <= index; ++i)
    {
        transaction::Output out{};
        out.value = reader.u64(); out.type = reader.u8();
        const auto payload = reader.varbytes(4'000'000);
        if (i == index)
        {
            out.payload.assign(payload.begin(), payload.end());
            return out;
        }
    }
    throw std::logic_error("Unreachable stored output");
}

transaction::Transaction transaction_base (Bytes raw)
{
    Reader reader(raw);
    transaction::Transaction tx{};
    tx.version = reader.u32();
    const auto inputs = reader.compact();
    if (inputs == 0 || inputs > reader.remaining() / 40)
        throw std::invalid_argument("Invalid transaction input count");
    for (std::uint64_t i = 0; i < inputs; ++i)
    {
        transaction::Input input{};
        const auto id = reader.bytes(32);
        std::copy(id.begin(), id.end(), input.previous_txid.begin());
        input.previous_index = reader.u32(); input.sequence = reader.u32();
        tx.inputs.push_back(input);
    }
    const auto outputs = reader.compact();
    if (outputs > reader.remaining() / 10) throw std::invalid_argument("Invalid transaction output count");
    for (std::uint64_t i = 0; i < outputs; ++i)
    {
        transaction::Output out{};
        out.value = reader.u64(); out.type = reader.u8();
        const auto payload = reader.varbytes(4'000'000);
        out.payload.assign(payload.begin(), payload.end());
        tx.outputs.push_back(std::move(out));
    }
    tx.lock_time = reader.u64();
    return tx;
}

std::size_t compact_size_bytes (std::uint64_t value)
{
    return value < 0xfd ? 1 : value <= 0xffff ? 3 : value <= 0xffffffffULL ? 5 : 9;
}

int compare_work (const Work &left, const Work &right) noexcept
{
    for (std::size_t i = left.size(); i-- > 0;)
    {
        if (left[i] < right[i])
            return -1;
        if (left[i] > right[i])
            return 1;
    }
    return 0;
}

std::array<std::uint64_t, 5> target_plus_one (const chain::Target256 &target)
{
    std::array<std::uint64_t, 5> result{};
    for (unsigned i = 0; i < 4; ++i)
    {
        std::uint64_t word = 0;
        for (unsigned j = 0; j < 8; ++j)
            word |= static_cast<std::uint64_t>(target[31 - (i * 8 + j)]) << (j * 8);
        result[i] = word;
    }
    for (std::size_t i = 0; i < result.size(); ++i)
    {
        if (++result[i] != 0)
            return result;
    }
    return result;
}

bool ge_257 (const std::array<std::uint64_t, 5> &a,
             const std::array<std::uint64_t, 5> &b) noexcept
{
    for (std::size_t i = a.size(); i-- > 0;)
    {
        if (a[i] > b[i])
            return true;
        if (a[i] < b[i])
            return false;
    }
    return true;
}

void subtract_257 (std::array<std::uint64_t, 5> &a,
                   const std::array<std::uint64_t, 5> &b) noexcept
{
    std::uint64_t borrow = 0;
    for (std::size_t i = 0; i < a.size(); ++i)
    {
        const auto first = a[i] - b[i];
        const auto borrow_first = a[i] < b[i];
        const auto second = first - borrow;
        const auto borrow_second = first < borrow;
        a[i] = second;
        borrow = static_cast<std::uint64_t>(borrow_first || borrow_second);
    }
}

Work block_work (std::uint32_t bits)
{
    const auto divisor = target_plus_one(chain::compact_to_target(bits));
    if (std::all_of(divisor.begin(), divisor.end(), [] (std::uint64_t n) { return n == 0; }))
        throw std::overflow_error("PoW target plus one overflowed");

    std::array<std::uint64_t, 5> remainder{};
    Work quotient{};
    for (int bit = 256; bit >= 0; --bit)
    {
        std::uint64_t carry = bit == 256 ? 1 : 0;
        for (std::size_t i = 0; i < remainder.size(); ++i)
        {
            const auto next = remainder[i] >> 63;
            remainder[i] = (remainder[i] << 1) | carry;
            carry = next;
        }
        if (ge_257(remainder, divisor))
        {
            subtract_257(remainder, divisor);
            quotient[static_cast<std::size_t>(bit) / 64] |=
                std::uint64_t{1} << (static_cast<unsigned>(bit) % 64);
        }
    }
    return quotient;
}

Work add_work (const Work &left, const Work &right)
{
    Work sum{};
    std::uint64_t carry = 0;
    for (std::size_t i = 0; i < sum.size(); ++i)
    {
        const auto first = left[i] + right[i];
        const auto carry_first = first < left[i];
        const auto second = first + carry;
        const auto carry_second = second < first;
        sum[i] = second;
        carry = static_cast<std::uint64_t>(carry_first || carry_second);
    }
    if (carry != 0)
        throw std::overflow_error("Cumulative chainwork exceeds 320 bits");
    return sum;
}

std::vector<std::uint8_t> encode_event (const merkle::Event &event)
{
    std::vector<std::uint8_t> out{event.type};
    out.insert(out.end(), event.body.begin(), event.body.end());
    return out;
}

std::vector<std::uint8_t> store_record (const Block &block)
{
    std::vector<std::uint8_t> out(store_magic.begin(), store_magic.end());
    const auto header = chain::serialize_header(block.header);
    out.insert(out.end(), header.begin(), header.end());
    write_compact(out, block.transactions.size());
    for (const auto &tx : block.transactions)
    {
        const auto raw = transaction::serialize(tx);
        write_varbytes(out, raw);
    }
    write_compact(out, block.events.size());
    for (const auto &event : block.events)
    {
        out.push_back(event.type);
        write_varbytes(out, event.id);
        write_varbytes(out, event.body);
    }
    return out;
}

std::size_t consensus_size (const Block &block)
{
    std::size_t size = rl::header_bytes + compact_size_bytes(block.transactions.size()) +
                       compact_size_bytes(block.events.size());
    for (const auto &tx : block.transactions)
    {
        const auto raw = transaction::serialize(tx);
        if (raw.size() > 4'000'000 - std::min<std::size_t>(size, 4'000'000))
            throw std::invalid_argument("Block exceeds 4,000,000-byte size limit");
        size += raw.size();
    }
    for (const auto &event : block.events)
    {
        const auto encoded = encode_event(event);
        if (encoded.size() > 4'000'000 - std::min<std::size_t>(size, 4'000'000))
            throw std::invalid_argument("Block exceeds 4,000,000-byte size limit");
        size += encoded.size();
    }
    if (size > 4'000'000)
        throw std::invalid_argument("Block exceeds 4,000,000-byte size limit");
    return size;
}

std::uint64_t now_seconds ()
{
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(now).count());
}

std::uint64_t median_time (std::span<const std::uint64_t> times)
{
    if (times.empty())
        return 0;
    std::vector<std::uint64_t> sorted(times.begin(), times.end());
    std::sort(sorted.begin(), sorted.end());
    return sorted[sorted.size() / 2];
}

void checked_sum (std::uint64_t &sum, std::uint64_t value)
{
    if (value > transaction::max_amount || sum > transaction::max_amount - value)
        throw std::invalid_argument("Block amount sum exceeds MAX_SUPPLY");
    sum += value;
}

bool has_qtl_input (const transaction::Transaction &tx) noexcept
{
    return std::any_of(tx.witnesses.begin(), tx.witnesses.end(), [] (const auto &witness) {
        return std::holds_alternative<transaction::BlockQtlWitness>(witness);
    });
}

std::string hex (Bytes bytes)
{
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (const auto byte : bytes)
    {
        result.push_back(digits[byte >> 4]);
        result.push_back(digits[byte & 0x0f]);
    }
    return result;
}

std::string id_hex (const Digest &id)
{
    return hex(id);
}
} // namespace

struct Node::Impl
{
    struct MempoolEntry
    {
        transaction::Transaction tx;
        Digest txid{};  // computed once on admission; lookups never rehash
        std::vector<std::uint8_t> raw;
        std::vector<OutPoint> inputs;
        bool qtl{};
        std::optional<merkle::Event> commit_event;
        std::optional<std::uint64_t> commit_height;
    };

    std::filesystem::path data_directory;
    std::filesystem::path blocks_directory;
    std::filesystem::path mempool_directory;
    std::map<Digest, IndexEntry> entries;
    Digest best{};
    State tip_state;
    std::map<Digest, Undo> undo;
    std::uint64_t validation_attempts{};
    std::vector<MempoolEntry> mempool;
    std::set<OutPoint> mempool_spends;
    std::uint64_t genesis_time{};
    std::uint32_t genesis_bits{chain::max_target_bits};
    std::optional<std::uint64_t> phase2_activation_height;
    // txid -> (block, position) in every stored block on any branch, so a
    // lookup never rescans or rehashes the chain (a peer's 1,000-ID inventory
    // used to cost one full rescan per ID).
    std::map<Digest, std::vector<std::pair<Digest, std::uint32_t>>> tx_index;
    // The active chain, genesis first, rebuilt only when the tip changes.
    mutable std::vector<Digest> active_cache;
    mutable Digest active_cache_tip{};

    explicit Impl (std::filesystem::path directory) : data_directory(std::move(directory))
    {
        if (data_directory.empty())
            throw std::invalid_argument("Node data directory must not be empty");
        blocks_directory = data_directory / "blocks";
        mempool_directory = data_directory / "mempool";
        std::filesystem::create_directories(blocks_directory);
        initialize_genesis();
        load_blocks();
        load_mempool();
    }

    // Each accepted transaction is published atomically before returning ACCEPTED.
    // These are public signed bytes, not wallet keys. Blocks remain authoritative.
    void persist_pending (const Digest &txid, Bytes raw) const
    {
        check_disk_floor();
        std::filesystem::create_directories(mempool_directory);
        const auto final_path = mempool_directory / (hex(txid) + ".tx");
        const auto pattern = (mempool_directory / ".pending-XXXXXX").string();
        std::vector<char> name(pattern.begin(), pattern.end());
        name.push_back('\0');
        int fd = ::mkstemp(name.data());
        if (fd < 0) throw std::runtime_error("Cannot create pending transaction file");
        try
        {
            std::size_t written = 0;
            while (written < raw.size())
            {
                const auto count = ::write(fd, raw.data() + written, raw.size() - written);
                if (count < 0 && errno == EINTR) continue;
                if (count <= 0) throw std::runtime_error("Cannot write pending transaction file");
                written += static_cast<std::size_t>(count);
            }
            if (::fsync(fd) != 0) throw std::runtime_error("Cannot flush pending transaction file");
            const auto closed = ::close(fd); fd = -1;
            if (closed != 0) throw std::runtime_error("Cannot close pending transaction file");
            std::filesystem::rename(name.data(), final_path);
        }
        catch (...)
        {
            if (fd >= 0) ::close(fd);
            std::error_code ignored;
            std::filesystem::remove(name.data(), ignored);
            throw;
        }
    }

    void load_mempool ()
    {
        if (!std::filesystem::exists(mempool_directory)) return;
        std::vector<std::filesystem::path> paths;
        for (const auto &entry : std::filesystem::directory_iterator(mempool_directory))
            if (entry.is_regular_file() && entry.path().extension() == ".tx")
                paths.push_back(entry.path());
        std::sort(paths.begin(), paths.end());
        std::set<std::string> confirmed;
        for (const auto &id : best_chain_ids())
            for (const auto &tx : historical_block(entries.at(id)).transactions)
                confirmed.insert(hex(transaction::txid(tx)));
        for (const auto &path : paths)
        {
            const auto name = path.stem().string();
            if (confirmed.contains(name)) continue;
            try
            {
                // No transaction is trusted merely because it exists on disk.
                // Recheck its signature, UTXOs, maturity and locks at the new tip.
                const auto raw = read_file(path);
                (void)submit_tx(raw, false, name);
            }
            catch (const std::exception &error)
            {
                std::cerr << "WARN ignoring pending transaction " << path.filename().string()
                          << ": " << error.what() << '\n';
            }
        }
    }

    void erase_pending (const Digest &txid) const
    {
        std::error_code error;
        std::filesystem::remove(mempool_directory / (hex(txid) + ".tx"), error);
        // A committed block must still be reported if cache cleanup fails.
        // On restart, confirmed transaction IDs are excluded from the mempool.
        if (error) std::cerr << "WARN pending-file cleanup: " << error.message() << '\n';
    }

    Block frozen_genesis ()
    {
        const std::string timestamp = "E46 08/Oct/2026 NASA’s SpaceX Crew‑12 Splashes Down, Sets Briefing to Discuss Mission";
        if (timestamp.size() != 89)
            throw std::logic_error("Frozen WO-10 testnet headline byte count changed");
        const auto *begin = reinterpret_cast<const std::uint8_t *>(timestamp.data());
        const auto mined = genesis::build(Bytes{begin, timestamp.size()}, 1'791'498'189,
                                          genesis_bits, 14'449'748, 56);
        if (!mined.pow_valid)
            throw std::logic_error("Frozen WO-10 testnet genesis no longer satisfies PoW");
        genesis_time = mined.header.time;
        Block result{};
        result.header = mined.header;
        result.transactions.push_back(mined.coinbase);
        return result;
    }

    std::string block_filename (std::uint64_t block_height, const Digest &id) const
    {
        std::string height_text = std::to_string(block_height);
        height_text.insert(height_text.begin(), 20 - height_text.size(), '0');
        return height_text + "-" + id_hex(id) + ".blk";
    }

    void check_disk_floor () const
    {
        const auto info = std::filesystem::space(data_directory);
        if (info.available < disk_floor_bytes)
            throw std::runtime_error("WO-17 disk safety stop: less than 1 GiB is available");
    }

    void persist_raw (Bytes bytes, std::uint64_t block_height, const Digest &id) const
    {
        check_disk_floor();
        const auto final_path = blocks_directory / block_filename(block_height, id);
        if (std::filesystem::exists(final_path))
            return;
        const auto temporary_path = final_path.string() + ".tmp";
        {
            std::ofstream stream(temporary_path, std::ios::binary | std::ios::trunc);
            if (!stream)
                throw std::runtime_error("Cannot create block store record");
            stream.write(reinterpret_cast<const char *>(bytes.data()),
                         static_cast<std::streamsize>(bytes.size()));
            stream.flush();
            if (!stream)
                throw std::runtime_error("Cannot write block store record");
        }
        std::filesystem::rename(temporary_path, final_path);
    }

    static std::vector<std::uint8_t> read_file (const std::filesystem::path &path)
    {
        const auto size = std::filesystem::file_size(path);
        if (size > 4'100'000)
            throw std::invalid_argument("Stored block record exceeds the implementation limit");
        std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
        std::ifstream stream(path, std::ios::binary);
        if (!stream)
            throw std::runtime_error("Cannot open block store record");
        stream.read(reinterpret_cast<char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (!stream || stream.peek() != std::char_traits<char>::eof())
            throw std::runtime_error("Cannot read complete block store record");
        return bytes;
    }

    // Lookups into the tip plus a per-block overlay allow in-block spends
    // without copying the complete coin set merely to decode witnesses.
    Block decode_record (Bytes bytes, bool historical = false) const
    {
        const auto parts = record_parts(bytes);
        Block block{parts.header, {}, parts.events};
        const auto parent = entries.find(block.header.prev_block);
        const auto child_height = parent == entries.end() ? 0 : parent->second.height + 1;
        UtxoSet created;
        std::set<OutPoint> consumed;
        for (std::size_t i = 0; i < parts.transactions.size(); ++i)
        {
            const auto raw = parts.transactions[i];
            const auto refs = transaction_inputs(raw);
            const bool coinbase = refs.size() == 1 && refs[0].index == 0xffffffffU && is_zero(refs[0].txid);
            std::vector<transaction::SpentCoin> spent;
            if (!coinbase)
                for (const auto &ref : refs)
                {
                    if (consumed.contains(ref))
                        throw std::invalid_argument("Stored transaction spends an unknown output");
                    const auto local = created.find(ref);
                    if (local != created.end()) spent.push_back(local->second);
                    else if (historical) spent.push_back(historical_coin(ref));
                    else
                    {
                        const auto found = tip_state.utxos.find(ref);
                        if (found == tip_state.utxos.end())
                            throw std::invalid_argument("Stored transaction spends an unknown output");
                        spent.push_back(found->second);
                    }
                }
            auto tx = transaction::deserialize(raw, spent);
            if (i == 0 && !coinbase) throw std::invalid_argument("Stored block does not begin with coinbase");
            if (!coinbase)
                for (const auto &ref : refs) { created.erase(ref); consumed.insert(ref); }
            const auto id = transaction::txid(tx);
            for (std::size_t j = 0; j < tx.outputs.size(); ++j)
                if (tx.outputs[j].type != 0x03)
                {
                    const OutPoint point{id, static_cast<std::uint32_t>(j)};
                    if (historical || consumed.contains(point) || !tip_state.utxos.contains(point))
                        created.emplace(point, transaction::SpentCoin{tx.outputs[j], coinbase, child_height});
                    consumed.erase(point);
                }
            block.transactions.push_back(std::move(tx));
        }
        return block;
    }

    transaction::SpentCoin historical_coin (const OutPoint &ref) const
    {
        const auto found = tx_index.find(ref.txid);
        if (found == tx_index.end()) throw std::invalid_argument("Historical transaction is unavailable");
        const auto &[id, pos] = found->second.front();
        const auto &entry = entries.at(id);
        const auto parts = record_parts(entry.raw);
        return {recorded_output(parts.transactions.at(pos), ref.index), pos == 0, entry.height};
    }

    Block historical_block (const IndexEntry &entry) const
    {
        if (!entry.validated || entry.invalid)
            throw std::invalid_argument("Block is not fully validated");
        return decode_record(entry.raw, true);
    }

    void initialize_genesis ()
    {
        const auto genesis_block = frozen_genesis();
        const auto header = chain::serialize_header(genesis_block.header);
        const auto id = addresses::block_id(header);
        tip_state.recent_times.push_back(genesis_block.header.time);
        const auto work = block_work(genesis_block.header.bits);
        const auto size = consensus_size(genesis_block);
        IndexEntry genesis_entry{genesis_block.header, store_record(genesis_block), id, {}, 0, work, {}, size, true, false};
        entries.emplace(id, std::move(genesis_entry));
        index_block(id, genesis_block);
        best = id;
        const auto path = blocks_directory / block_filename(0, id);
        if (!std::filesystem::exists(path))
            persist_raw(entries.at(id).raw, 0, id);
    }

    void load_blocks ()
    {
        std::vector<std::filesystem::path> paths;
        for (const auto &entry : std::filesystem::directory_iterator(blocks_directory))
        {
            if (entry.is_regular_file() && entry.path().extension() == ".blk")
                paths.push_back(entry.path());
        }
        std::sort(paths.begin(), paths.end());
        for (const auto &path : paths)
        {
            const auto dash = path.filename().string().find('-');
            if (dash == std::string::npos)
                throw std::invalid_argument("Malformed block store filename");
            const auto block_height = std::stoull(path.filename().string().substr(0, dash));
            const auto bytes = read_file(path);
            if (block_height == 0)
            {
                const auto expected_block = frozen_genesis();
                const auto expected = store_record(expected_block);
                if (bytes != expected || path.filename() != block_filename(0, entries.at(best).id))
                    throw std::invalid_argument("Local store genesis differs from frozen testnet genesis");
                continue;
            }
            const auto result = accept_record(bytes, now_seconds(), false);
            if (result.height != block_height || block_filename(result.height, result.id) != path.filename().string())
                throw std::invalid_argument("Stored block path does not match validated contents");
        }
    }

    BlockInfo make_info (const IndexEntry &entry) const
    {
        return {historical_block(entry), entry.id, entry.height, entry.pools, entry.size};
    }

    std::optional<CommitAtHeight> find_commitment (const transaction::Transaction &tx,
                                                    const State &state,
                                                    std::uint64_t at_height) const
    {
        const auto commitment = block_qtl::make_commitment(tx);
        const auto found = state.commitments.find(commitment);
        if (found == state.commitments.end())
            return std::nullopt;
        for (auto item = found->second.rbegin(); item != found->second.rend(); ++item)
        {
            const auto depth = at_height >= item->height ? at_height - item->height : 0;
            if (depth >= block_qtl::min_reveal_depth && depth <= block_qtl::max_reveal_depth &&
                block_qtl::verify_reveal(tx, item->event, depth, block_qtl::provisional_z_commit))
                return *item;
        }
        return std::nullopt;
    }

    std::optional<CommitAtHeight> find_any_commitment (const transaction::Transaction &tx,
                                                        const State &state) const
    {
        const auto commitment = block_qtl::make_commitment(tx);
        const auto found = state.commitments.find(commitment);
        if (found == state.commitments.end() || found->second.empty())
            return std::nullopt;
        return found->second.back();
    }

    void validate_tx_lock (const transaction::Transaction &tx, const State &parent_state,
                           std::uint64_t block_height) const
    {
        if (tx.lock_time == 0 || std::all_of(tx.inputs.begin(), tx.inputs.end(), [] (const auto &input) {
                return input.sequence == 0xffffffffU;
            }))
            return;
        const auto comparison = tx.lock_time < 500'000'000ULL
            ? block_height : median_time(parent_state.recent_times);
        if (comparison <= tx.lock_time)
            throw std::invalid_argument("Transaction is non-final at this block height/time");
    }

    static std::uint64_t output_total (std::span<const transaction::Output> outputs)
    {
        std::uint64_t total = 0;
        for (const auto &output : outputs)
            checked_sum(total, output.value);
        return total;
    }

    void add_outputs (State &state, const transaction::Transaction &tx,
                      std::uint64_t height, bool coinbase, Undo &changes) const
    {
        const auto txid = transaction::txid(tx);
        for (std::size_t i = 0; i < tx.outputs.size(); ++i)
        {
            const auto &output = tx.outputs[i];
            if (output.type == 0x03)
                continue;
            if (output.type == 0x02 && !phase2_activation_height)
                throw std::invalid_argument("Stake-lock output is disabled until Phase 2 activation");
            remember_coin(changes, OutPoint{txid, static_cast<std::uint32_t>(i)});
            state.utxos.emplace(OutPoint{txid, static_cast<std::uint32_t>(i)},
                                transaction::SpentCoin{output, coinbase, height});
        }
    }

    void remember_coin (Undo &changes, const OutPoint &point) const
    {
        if (changes.coins.contains(point)) return;
        const auto found = tip_state.utxos.find(point);
        changes.coins.emplace(point, found == tip_state.utxos.end()
            ? std::nullopt : std::optional<transaction::SpentCoin>(found->second));
    }

    void restore (const Undo &changes)
    {
        for (const auto &[point, coin] : changes.coins)
        {
            if (coin) tip_state.utxos.insert_or_assign(point, *coin);
            else tip_state.utxos.erase(point);
        }
        for (auto it = changes.commitments.rbegin(); it != changes.commitments.rend(); ++it)
        {
            auto &values = tip_state.commitments.at(*it);
            values.pop_back();
            if (values.empty()) tip_state.commitments.erase(*it);
        }
        tip_state.pools = changes.pools;
        tip_state.recent_times = changes.recent_times;
    }

    std::vector<std::uint64_t> ancestor_times (Digest id) const
    {
        std::vector<std::uint64_t> times;
        while (times.size() < 11)
        {
            const auto &entry = entries.at(id);
            times.push_back(entry.header.time);
            if (entry.height == 0) break;
            id = entry.parent;
        }
        std::reverse(times.begin(), times.end());
        return times;
    }

    void connect (IndexEntry &entry)
    {
        if (entry.invalid) throw std::invalid_argument("Block is known invalid");
        if (entry.parent != best) throw std::logic_error("Connect must extend the active state");
        ++validation_attempts;
        const auto block = decode_record(entry.raw);
        const auto block_height = entry.height;
        Undo changes{};
        changes.pools = tip_state.pools;
        changes.recent_times = tip_state.recent_times;
        changes.commitments.reserve(block.events.size());
        try
        {
            const auto size = consensus_size(block);
            if (block.transactions.empty() || !transaction::is_coinbase(block.transactions.front()))
                throw std::invalid_argument("Block must begin with one coinbase transaction");
            std::vector<Digest> txids;
            std::vector<Digest> wtxids;
            txids.reserve(block.transactions.size());
            wtxids.reserve(block.transactions.size());
            std::set<Digest> unique_txids;
            for (const auto &tx : block.transactions)
            {
                const auto txid = transaction::txid(tx);
                if (!unique_txids.insert(txid).second)
                    throw std::invalid_argument("Duplicate transaction ID in block");
                txids.push_back(txid);
                wtxids.push_back(transaction::wtxid(tx));
            }
            if (merkle::merkle_root(txids) != block.header.merkle_root)
                throw std::invalid_argument("Transaction Merkle root mismatch");

            const auto &coinbase = block.transactions.front();
            transaction::validate_coinbase(coinbase, block_height);
            if (coinbase.outputs.empty())
                throw std::invalid_argument("Coinbase has no witness commitment output");
            const auto commitment = transaction::witness_commitment(wtxids);
            const auto &last_output = coinbase.outputs.back();
            if (last_output.type != 0x03 || last_output.value != 0 || last_output.payload.size() != commitment.size() ||
                !std::equal(last_output.payload.begin(), last_output.payload.end(), commitment.begin()) ||
                !transaction::has_witness_commitment(coinbase, commitment))
                throw std::invalid_argument("Coinbase final output is not the unique witness commitment");

            auto &next = tip_state;
            add_outputs(next, coinbase, block_height, true, changes);
            std::uint64_t fees = 0;
            for (std::size_t tx_index = 1; tx_index < block.transactions.size(); ++tx_index)
            {
                const auto &tx = block.transactions[tx_index];
                if (transaction::is_coinbase(tx))
                    throw std::invalid_argument("A block may contain only one coinbase");
                std::vector<transaction::SpentCoin> spent;
                spent.reserve(tx.inputs.size());
                std::set<OutPoint> used;
                std::uint64_t input_value = 0;
                for (const auto &input : tx.inputs)
                {
                    const OutPoint outpoint{input.previous_txid, input.previous_index};
                    if (!used.insert(outpoint).second)
                        throw std::invalid_argument("Transaction repeats an input outpoint");
                    const auto found = next.utxos.find(outpoint);
                    if (found == next.utxos.end())
                        throw std::invalid_argument("Transaction spends an unknown or already-spent output");
                    if (found->second.output.type == 0x02 && !phase2_activation_height)
                        throw std::invalid_argument("Stake-lock outputs are disabled until Phase 2 activation");
                    checked_sum(input_value, found->second.output.value);
                    spent.push_back(found->second);
                }
                transaction::validate_transaction(tx, spent, block_height);
                validate_tx_lock(tx, tip_state, block_height);
                if (has_qtl_input(tx) && !find_commitment(tx, tip_state, block_height))
                    throw std::invalid_argument("Block QTL reveal has no matching commitment at valid depth");
                const auto output_value = output_total(tx.outputs);
                if (output_value > input_value)
                    throw std::invalid_argument("Transaction outputs exceed its inputs");
                checked_sum(fees, input_value - output_value);
                for (const auto &output : tx.outputs)
                {
                    if (output.type == 0x02 && !phase2_activation_height)
                        throw std::invalid_argument("Stake-lock output is disabled until Phase 2 activation");
                }
                for (const auto &input : tx.inputs)
                {
                    const OutPoint point{input.previous_txid, input.previous_index};
                    remember_coin(changes, point);
                    next.utxos.erase(point);
                }
                add_outputs(next, tx, block_height, false, changes);
            }

            const auto reward = emission::reward_at(block_height);
            const auto shares = emission::split_reward(reward);
            const auto expected_miner_value = shares.miner + fees;
            if (expected_miner_value > transaction::max_amount || output_total(coinbase.outputs) != expected_miner_value)
                throw std::invalid_argument("Coinbase does not pay exactly the Phase-1 miner share plus fees");
            next.pools = emission::accrue_pools(tip_state.pools, reward);

            const auto ordered = merkle::sorted_events(block.events);
            if (ordered.size() != block.events.size())
                throw std::invalid_argument("Event sorting changed event count");
            for (std::size_t i = 0; i < ordered.size(); ++i)
            {
                if (ordered[i].type != block.events[i].type || ordered[i].id != block.events[i].id ||
                    ordered[i].body != block.events[i].body)
                    throw std::invalid_argument("Block events are not in canonical (type, ID) order");
                if (ordered[i].type == 0x02)
                    throw std::invalid_argument("Rad events are disabled until Phase 2 activation");
                if (ordered[i].type != block_qtl::event_type)
                    throw std::invalid_argument("Unknown block event type");
            }
            block_qtl::validate_block_events(block.events, block_qtl::provisional_z_commit);
            if (merkle::event_root(block.events) != block.header.event_root)
                throw std::invalid_argument("Block event_root mismatch");
            for (const auto &event : block.events)
            {
                if (event.type == block_qtl::event_type)
                {
                    Commitment key{};
                    std::copy(event.id.begin(), event.id.end(), key.begin());
                    next.commitments[key].push_back({event, block_height});
                    changes.commitments.push_back(key);
                }
            }
            next.recent_times.push_back(block.header.time);
            if (next.recent_times.size() > 11)
                next.recent_times.erase(next.recent_times.begin(), next.recent_times.end() - 11);


            entry.pools = tip_state.pools;
            entry.size = size;
            if (!entry.validated) index_block(entry.id, block);
            entry.validated = true;
            undo.emplace(entry.id, std::move(changes));
            best = entry.id;
        }
        catch (...)
        {
            restore(changes);
            throw;
        }
    }

    void disconnect ()
    {
        const auto previous = entries.at(best).parent;
        restore(undo.at(best));
        undo.erase(best);
        best = previous;
    }

    std::filesystem::path rejection_path (const Digest &id) const
    {
        return data_directory / "rejected" / (hex(id) + ".txt");
    }

    void mark_invalid (const Digest &failed, const std::string &reason, bool persist_rejection)
    {
        for (auto &[id, entry] : entries)
        {
            auto cursor = id;
            while (entries.at(cursor).height && cursor != failed) cursor = entries.at(cursor).parent;
            if (cursor != failed) continue;
            entry.invalid = true;
            if (persist_rejection && std::filesystem::exists(blocks_directory / block_filename(entry.height, id)))
            {
                // Bind local rejection metadata to the exact raw record. A later
                // damaged record must fail replay, not be silently excluded.
                const auto path = rejection_path(id);
                std::filesystem::create_directories(path.parent_path());
                std::ofstream out(path, std::ios::trunc);
                out << hex(shake::shake256_tagged_256("E46-rejected-record", entry.raw)) << '\n';
                out.flush();
                if (!out) throw std::runtime_error("Cannot preserve rejected branch metadata");
            }
        }
        std::cerr << "Rejected branch " << hex(failed) << ": " << reason << '\n';
    }

    void activate (const Digest &target, bool persist_rejection, bool restoring = false)
    {
        if (!restoring && compare_work(entries.at(target).chainwork, entries.at(best).chainwork) <= 0) return;
        const auto original = best;
        auto left = best, right = target;
        std::vector<Digest> old_chain, new_chain;
        while (left != right)
        {
            if (entries.at(left).height >= entries.at(right).height)
            { old_chain.push_back(left); left = entries.at(left).parent; }
            else
            { new_chain.push_back(right); right = entries.at(right).parent; }
        }
        const auto fork = left;
        for (std::size_t i = 0; i < old_chain.size(); ++i) disconnect();
        Digest connecting = target;
        try
        {
            for (auto it = new_chain.rbegin(); it != new_chain.rend(); ++it)
            { connecting = *it; connect(entries.at(*it)); }
        }
        catch (const std::exception &error)
        {
            const std::string reason = error.what();
            while (best != fork) disconnect();
            for (auto it = old_chain.rbegin(); it != old_chain.rend(); ++it) connect(entries.at(*it));
            if (best != original) throw std::logic_error("Branch rollback did not restore the original tip");
            mark_invalid(connecting, reason, persist_rejection);
            throw std::invalid_argument("Invalid competing branch: " + reason);
        }
    }

    std::size_t check_body_without_coins (const RecordParts &parts, std::uint64_t height) const
    {
        std::vector<Digest> txids, wtxids;
        std::set<Digest> unique;
        std::size_t size = rl::header_bytes + compact_size_bytes(parts.transactions.size()) + compact_size_bytes(parts.events.size());
        for (std::size_t i = 0; i < parts.transactions.size(); ++i)
        {
            const auto raw = parts.transactions[i];
            const auto base = transaction_base(raw);
            if (transaction::is_coinbase(base) != (i == 0))
                throw std::invalid_argument("Block must begin with exactly one coinbase");
            const auto id = transaction::txid(base);
            if (!unique.insert(id).second) throw std::invalid_argument("Duplicate transaction ID in block");
            txids.push_back(id); wtxids.push_back(addresses::wtxid(raw));
            size += raw.size();
        }
        if (merkle::merkle_root(txids) != parts.header.merkle_root)
            throw std::invalid_argument("Transaction Merkle root mismatch");
        const auto coinbase = transaction::deserialize(parts.transactions.front());
        transaction::validate_coinbase(coinbase, height);
        const auto commitment = transaction::witness_commitment(wtxids);
        if (coinbase.outputs.empty()) throw std::invalid_argument("Coinbase has no witness commitment output");
        const auto &last = coinbase.outputs.back();
        if (last.type != 0x03 || last.value != 0 || last.payload.size() != commitment.size() ||
            !std::equal(last.payload.begin(), last.payload.end(), commitment.begin()) ||
            !transaction::has_witness_commitment(coinbase, commitment))
            throw std::invalid_argument("Coinbase final output is not the unique witness commitment");
        const auto ordered = merkle::sorted_events(parts.events);
        for (std::size_t i = 0; i < ordered.size(); ++i)
        {
            if (ordered[i].type != parts.events[i].type || ordered[i].id != parts.events[i].id || ordered[i].body != parts.events[i].body)
                throw std::invalid_argument("Block events are not in canonical (type, ID) order");
            if (ordered[i].type == 0x02) throw std::invalid_argument("Rad events are disabled until Phase 2 activation");
            if (ordered[i].type != block_qtl::event_type) throw std::invalid_argument("Unknown block event type");
            size += encode_event(ordered[i]).size();
        }
        block_qtl::validate_block_events(parts.events, block_qtl::provisional_z_commit);
        if (merkle::event_root(parts.events) != parts.header.event_root)
            throw std::invalid_argument("Block event_root mismatch");
        if (size > 4'000'000) throw std::invalid_argument("Block exceeds 4,000,000-byte size limit");
        return size;
    }

    BlockInfo accept_record (Bytes raw, std::uint64_t adjusted_time, bool write_record)
    {
        const auto parts = record_parts(raw);
        const auto &header = parts.header;
        const auto parent_it = entries.find(header.prev_block);
        if (parent_it == entries.end()) throw std::invalid_argument("Block parent is unknown");
        const auto &parent = parent_it->second;
        const auto id = addresses::block_id(chain::serialize_header(header));
        if (const auto known = entries.find(id); known != entries.end())
            throw std::invalid_argument(known->second.invalid ? "Block is known invalid" : "Block is already known");
        if (write_record && parent.invalid) throw std::invalid_argument("Block descends from an invalid branch");
        if (parent.height == UINT64_MAX) throw std::overflow_error("Block height overflow");
        const auto height = parent.height + 1;
        checkpoints::validate_testnet(height, id);
        const auto expected = chain::asert_bits(genesis_bits, 0, genesis_time - chain::target_spacing,
                                                parent.height, parent.header.time);
        if (header.bits != expected) throw std::invalid_argument("Block bits do not match ASERT");
        if (!chain::check_block_time(header.time, ancestor_times(parent.id), adjusted_time))
            throw std::invalid_argument("Block time violates median-time-past or future-time limit");
        if (!chain::check_header_pow(header)) throw std::invalid_argument("Block proof of work is invalid");
        const auto size = check_body_without_coins(parts, height);
        IndexEntry entry{header, {raw.begin(), raw.end()}, id, parent.id, height,
            add_work(parent.chainwork, block_work(header.bits)),
            emission::accrue_pools(parent.pools, emission::reward_at(height)), size, false, parent.invalid};
        if (!write_record && std::filesystem::exists(rejection_path(id)))
        {
            std::ifstream in(rejection_path(id));
            std::string fingerprint; std::getline(in, fingerprint);
            if (!in || fingerprint != hex(shake::shake256_tagged_256("E46-rejected-record", raw)))
                throw std::invalid_argument("Rejected block record or metadata is damaged");
            entry.invalid = true;
        }
        if (write_record) check_disk_floor();
        auto &stored = entries.emplace(id, std::move(entry)).first->second;
        const auto original = best;
        if (!stored.invalid) activate(id, write_record);
        try
        {
            if (write_record) persist_raw(raw, height, id);
        }
        catch (...)
        {
            if (best != original) activate(original, false, true);
            for (auto it = tx_index.begin(); it != tx_index.end();)
            {
                std::erase_if(it->second, [&](const auto &location) { return location.first == id; });
                if (it->second.empty()) it = tx_index.erase(it); else ++it;
            }
            entries.erase(id);
            throw;
        }
        if (stored.validated && !stored.invalid) return make_info(stored);
        // Deferred branch admission has only a header until activation. Public
        // get_block refuses to present its body as a fully validated block.
        return {Block{header, {}, {}}, id, height, stored.pools, stored.size};
    }

    BlockInfo accept_internal (const Block &block, std::uint64_t adjusted_time, bool write_record)
    {
        return accept_record(store_record(block), adjusted_time, write_record);
    }

    const std::vector<Digest> &best_chain_ids () const
    {
        if (active_cache.empty() || active_cache_tip != best)
        {
            std::vector<Digest> result;
            auto current = best;
            while (true)
            {
                result.push_back(current);
                const auto &entry = entries.at(current);
                if (entry.height == 0)
                    break;
                current = entry.parent;
            }
            std::reverse(result.begin(), result.end());
            active_cache = std::move(result);
            active_cache_tip = best;
        }
        return active_cache;
    }

    void index_block (const Digest &id, const Block &block)
    {
        const auto &transactions = block.transactions;
        for (std::size_t i = 0; i < transactions.size(); ++i)
            tx_index[transaction::txid(transactions[i])].emplace_back(id, static_cast<std::uint32_t>(i));
    }

    // The active-chain copy of a confirmed transaction, or nullptr.
    std::optional<std::pair<Digest, std::uint32_t>> active_transaction (const Digest &txid) const
    {
        const auto found = tx_index.find(txid);
        if (found == tx_index.end())
            return std::nullopt;
        const auto &active = best_chain_ids();
        for (const auto &[block_id, position] : found->second)
        {
            const auto &entry = entries.at(block_id);
            const auto height = static_cast<std::size_t>(entry.height);
            if (height < active.size() && active[height] == block_id)
                return std::pair{block_id, position};
        }
        return std::nullopt;
    }

    const IndexEntry &active_tip () const
    {
        return entries.at(best);
    }

    std::vector<transaction::SpentCoin> spent_for (std::span<const OutPoint> inputs,
                                                    const State &state) const
    {
        std::vector<transaction::SpentCoin> result;
        result.reserve(inputs.size());
        std::set<OutPoint> unique;
        for (const auto &input : inputs)
        {
            if (!unique.insert(input).second)
                throw std::invalid_argument("Transaction repeats an input outpoint");
            const auto found = state.utxos.find(input);
            if (found == state.utxos.end())
                throw std::invalid_argument("Transaction spends an unknown or already-spent output");
            if (found->second.output.type == 0x02 && !phase2_activation_height)
                throw std::invalid_argument("Stake-lock outputs are disabled until Phase 2 activation");
            result.push_back(found->second);
        }
        return result;
    }

    bool known_transaction (const Digest &wanted) const
    {
        if (active_transaction(wanted))
            return true;
        return std::any_of(mempool.begin(), mempool.end(), [&wanted] (const auto &entry) {
            return entry.txid == wanted;
        });
    }

    std::string submit_tx (Bytes raw, bool persist_entry = true,
                           std::string_view expected_id = {}, bool allow_qtl_work = true,
                           const std::optional<merkle::Event> *prepared_commit = nullptr)
    {
        if (raw.empty() || raw.size() > 4'000'000)
            throw std::invalid_argument("Submitted transaction size outside block limit");
        const auto refs = transaction_inputs(raw);
        if (refs.size() == 1 && refs[0].index == 0xffffffffU && is_zero(refs[0].txid))
            throw std::invalid_argument("Cannot submit a coinbase transaction");
        const auto &tip = active_tip();
        const auto candidate_height = tip.height + 1;
        const auto spent = spent_for(refs, tip_state);
        const auto tx = transaction::deserialize(raw, spent);
        transaction::validate_transaction(tx, spent, candidate_height);
        validate_tx_lock(tx, tip_state, candidate_height);
        for (const auto &output : tx.outputs)
        {
            if (output.type == 0x02 && !phase2_activation_height)
                throw std::invalid_argument("Stake-lock outputs are disabled until Phase 2 activation");
        }
        const auto txid = transaction::txid(tx);
        if (!expected_id.empty() && hex(txid) != expected_id)
            throw std::invalid_argument("Pending filename does not match transaction ID");
        if (known_transaction(txid))
            throw std::invalid_argument("Transaction is already known");
        for (const auto &input : refs)
            if (mempool_spends.contains(input))
                throw std::invalid_argument("Mempool double spend");
        std::size_t pending_bytes = raw.size();
        for (const auto &entry : mempool) pending_bytes += entry.raw.size();
        if (mempool.size() >= 1000 || pending_bytes > 64 * 1024 * 1024)
            throw std::invalid_argument("Local mempool limit reached (1000 transactions / 64 MiB)");

        MempoolEntry entry{};
        entry.tx = tx;
        entry.txid = txid;
        entry.raw.assign(raw.begin(), raw.end());
        entry.inputs = refs;
        entry.qtl = has_qtl_input(tx);
        if (entry.qtl)
        {
            const auto existing = find_any_commitment(tx, tip_state);
            if (existing)
            {
                if (candidate_height - existing->height <= block_qtl::max_reveal_depth)
                    entry.commit_height = existing->height;
            }
            else
            {
                if (prepared_commit && *prepared_commit) entry.commit_event = *prepared_commit;
                else
                {
                    if (!allow_qtl_work)
                        throw std::invalid_argument("QTL relay requires an existing on-chain commitment");
                    entry.commit_event = block_qtl::mine_event(tx, block_qtl::provisional_z_commit, 4);
                }
            }
        }
        if (persist_entry) persist_pending(txid, raw);
        for (const auto &input : refs)
            mempool_spends.insert(input);
        mempool.push_back(std::move(entry));
        return mempool.back().qtl ? "ACCEPTED: Block QTL reveal queued for its commitment depth" : "ACCEPTED";
    }

    Block make_candidate (const IndexEntry &parent, const AddressPayload &miner,
                          std::vector<std::size_t> &included_mempool,
                          std::vector<std::size_t> &new_commit_events) const
    {
        const auto block_height = parent.height + 1;
        Block block{};
        std::uint64_t timestamp = std::max(now_seconds(), median_time(tip_state.recent_times) + 1);
        if (timestamp > now_seconds() + chain::max_future_seconds)
            throw std::runtime_error("Local clock is behind median-time-past by more than the future limit");

        if (parent.id == best)
        {
            for (std::size_t i = 0; i < mempool.size(); ++i)
            {
                const auto &entry = mempool[i];
                bool spendable = true;
                try
                {
                    const auto spent = spent_for(entry.inputs, tip_state);
                    transaction::validate_transaction(entry.tx, spent, block_height);
                    validate_tx_lock(entry.tx, tip_state, block_height);
                }
                catch (const std::exception &)
                {
                    spendable = false;
                }
                if (!spendable)
                    continue;
                if (!entry.qtl)
                {
                    included_mempool.push_back(i);
                    continue;
                }
                const auto any_commitment = find_any_commitment(entry.tx, tip_state);
                if (entry.commit_event && !any_commitment)
                {
                    block.events.push_back(*entry.commit_event);
                    new_commit_events.push_back(i);
                    continue;
                }
                const auto committed = find_commitment(entry.tx, tip_state, block_height);
                if (committed)
                    included_mempool.push_back(i);
                else if (any_commitment)
                {
                    const auto depth = block_height >= any_commitment->height
                        ? block_height - any_commitment->height : 0;
                    if (depth < block_qtl::min_reveal_depth)
                        continue;
                    if (depth > block_qtl::max_reveal_depth && !entry.commit_height)
                    {
                        block.events.push_back(block_qtl::mine_event(
                            entry.tx, block_qtl::provisional_z_commit, 4));
                        new_commit_events.push_back(i);
                    }
                }
            }
        }
        const auto sorted = merkle::sorted_events(block.events);
        block.events = sorted;
        for (const auto index : included_mempool)
            block.transactions.push_back(mempool[index].tx);

        std::uint64_t fees = 0;
        for (const auto index : included_mempool)
        {
            const auto &tx = mempool[index].tx;
            const auto refs = mempool[index].inputs;
            const auto spent = spent_for(refs, tip_state);
            std::uint64_t in = 0;
            for (const auto &coin : spent)
                checked_sum(in, coin.output.value);
            const auto out = output_total(tx.outputs);
            if (out > in)
                throw std::invalid_argument("Mempool transaction outputs exceed inputs");
            checked_sum(fees, in - out);
        }
        const auto reward = emission::reward_at(block_height);
        const auto shares = emission::split_reward(reward);
        std::uint64_t miner_value = shares.miner;
        checked_sum(miner_value, fees);

        transaction::Transaction coinbase{};
        coinbase.version = 1;
        coinbase.inputs.push_back({Digest{}, 0xffffffffU, 0xffffffffU});
        coinbase.outputs.push_back({miner_value, 0x00, {miner.begin(), miner.end()}});
        coinbase.outputs.push_back({0, 0x03, std::vector<std::uint8_t>(32)});
        coinbase.lock_time = block_height;
        coinbase.witnesses.emplace_back(transaction::CoinbaseWitness{std::vector<std::uint8_t>(8, 0)});
        block.transactions.insert(block.transactions.begin(), coinbase);

        std::vector<Digest> wtxids;
        wtxids.reserve(block.transactions.size());
        for (const auto &tx : block.transactions)
            wtxids.push_back(transaction::wtxid(tx));
        const auto commitment = transaction::witness_commitment(wtxids);
        block.transactions.front().outputs.back().payload.assign(commitment.begin(), commitment.end());

        std::vector<Digest> txids;
        txids.reserve(block.transactions.size());
        for (const auto &tx : block.transactions)
            txids.push_back(transaction::txid(tx));

        block.header.version = 1;
        block.header.prev_block = parent.id;
        block.header.merkle_root = merkle::merkle_root(txids);
        block.header.event_root = merkle::event_root(block.events);
        block.header.time = timestamp;
        block.header.bits = chain::asert_bits(genesis_bits, 0, genesis_time - chain::target_spacing,
                                              parent.height, parent.header.time);
        block.header.nonce = 0;
        return block;
    }

    void mine_header (Block &block, std::uint32_t workers) const
    {
        if (workers == 0 || workers > 4)
            throw std::invalid_argument("Local miner supports 1..4 workers");
        const auto target = chain::compact_to_target(block.header.bits);
        std::atomic<std::uint64_t> best_nonce{UINT64_MAX};
        std::atomic<bool> found{false};
        std::vector<std::thread> threads;
        threads.reserve(workers);
        for (std::uint32_t worker = 0; worker < workers; ++worker)
        {
            threads.emplace_back([&, worker] {
                auto header = block.header;
                std::uint64_t nonce = worker;
                while (true)
                {
                    if (found.load(std::memory_order_acquire) &&
                        nonce > best_nonce.load(std::memory_order_relaxed))
                        break;
                    header.nonce = nonce;
                    const auto bytes = chain::serialize_header(header);
                    if (rl::rl_v3_header_pow(bytes, target))
                    {
                        auto current = best_nonce.load(std::memory_order_relaxed);
                        while (nonce < current &&
                               !best_nonce.compare_exchange_weak(current, nonce,
                                   std::memory_order_relaxed, std::memory_order_relaxed))
                        {
                        }
                        found.store(true, std::memory_order_release);
                    }
                    if (nonce > UINT64_MAX - workers)
                        break;
                    nonce += workers;
                }
            });
        }
        for (auto &thread : threads)
            thread.join();
        if (!found.load(std::memory_order_acquire))
            throw std::runtime_error("Local miner exhausted nonce space");
        block.header.nonce = best_nonce.load(std::memory_order_relaxed);
    }

    BlockInfo mine_one (const Digest &parent_id, const AddressPayload &miner,
                        std::uint32_t workers, std::optional<std::uint64_t> time)
    {
        const auto parent_it = entries.find(parent_id);
        if (parent_it == entries.end())
            throw std::invalid_argument("Cannot mine on an unknown parent");
        if (parent_id != best) throw std::invalid_argument("mine_on requires the active tip; use a separate datadir for branch mining");
        std::vector<std::size_t> included;
        std::vector<std::size_t> new_commits;
        auto block = make_candidate(parent_it->second, miner, included, new_commits);
        if (time)
        {
            block.header.time = *time;
            if (block.header.time <= median_time(tip_state.recent_times))
                throw std::invalid_argument("Requested mining time is not later than median-time-past");
        }
        mine_header(block, workers);
        const auto result = accept_internal(block, now_seconds(), true);
        for (const auto index : new_commits)
        {
            if (index < mempool.size())
                mempool[index].commit_height = result.height;
        }
        if (parent_id == best || result.id == best)
            remove_mined(included);
        return result;
    }

    void remove_mined (std::vector<std::size_t> indices)
    {
        std::sort(indices.begin(), indices.end());
        indices.erase(std::unique(indices.begin(), indices.end()), indices.end());
        for (auto it = indices.rbegin(); it != indices.rend(); ++it)
        {
            if (*it >= mempool.size())
                continue;
            for (const auto &input : mempool[*it].inputs)
                mempool_spends.erase(input);
            erase_pending(mempool[*it].txid);
            mempool.erase(mempool.begin() + static_cast<std::ptrdiff_t>(*it));
        }
    }
};

std::vector<std::uint8_t> serialize_block (const Block &block)
{
    std::vector<std::uint8_t> result;
    const auto header = chain::serialize_header(block.header);
    result.insert(result.end(), header.begin(), header.end());
    write_compact(result, block.transactions.size());
    for (const auto &tx : block.transactions)
    {
        const auto raw = transaction::serialize(tx);
        result.insert(result.end(), raw.begin(), raw.end());
    }
    write_compact(result, block.events.size());
    for (const auto &event : block.events)
    {
        const auto raw = encode_event(event);
        result.insert(result.end(), raw.begin(), raw.end());
    }
    return result;
}

Node::Node (std::filesystem::path data_directory) : impl_(new Impl(std::move(data_directory))) {}
Node::~Node () { delete impl_; }
Node::Node (Node &&other) noexcept : impl_(std::exchange(other.impl_, nullptr)) {}
Node &Node::operator= (Node &&other) noexcept
{
    if (this != &other)
    {
        delete impl_;
        impl_ = std::exchange(other.impl_, nullptr);
    }
    return *this;
}

StorageStats Node::storage_stats () const
{
    StorageStats stats{};
    stats.tip_coins = impl_->tip_state.utxos.size();
    stats.undo_records = impl_->undo.size();
    stats.indexed_blocks = impl_->entries.size();
    stats.validation_attempts = impl_->validation_attempts;
    for (const auto &[id, changes] : impl_->undo)
    {
        (void)id;
        for (const auto &[point, coin] : changes.coins)
        {
            (void)point;
            if (coin) ++stats.undo_saved_coins; else ++stats.undo_created_outputs;
        }
    }
    for (const auto &[id, entry] : impl_->entries)
    { (void)id; if (entry.invalid) ++stats.invalid_blocks; }
    return stats;
}

std::uint64_t Node::height () const { return impl_->active_tip().height; }
Digest Node::tip_id () const { return impl_->best; }
emission::PoolBalances Node::pool_balances () const { return impl_->tip_state.pools; }

std::uint64_t Node::balance (const AddressPayload &address) const
{
    std::uint64_t total = 0;
    for (const auto &[outpoint, coin] : impl_->tip_state.utxos)
    {
        (void)outpoint;
        if (coin.output.type == 0x00 && coin.output.payload.size() == address.size() &&
            std::equal(coin.output.payload.begin(), coin.output.payload.end(), address.begin()))
            checked_sum(total, coin.output.value);
    }
    return total;
}

std::vector<OwnedCoin> Node::coins (const AddressPayload &address) const
{
    const auto &tip = impl_->active_tip();
    const auto spending_height = tip.height + 1;
    std::vector<OwnedCoin> result;
    for (const auto &[outpoint, coin] : impl_->tip_state.utxos)
    {
        if (coin.output.type != 0x00 || coin.output.payload.size() != address.size() ||
            !std::equal(coin.output.payload.begin(), coin.output.payload.end(), address.begin()))
            continue;
        OwnedCoin owned{outpoint.txid, outpoint.index, coin, 0, impl_->mempool_spends.contains(outpoint)};
        // Same rule as transaction validation: a coinbase output needs 100 blocks.
        if (coin.is_coinbase && spending_height < coin.creation_height + transaction::coinbase_maturity)
            owned.blocks_to_maturity = coin.creation_height + transaction::coinbase_maturity - spending_height;
        result.push_back(owned);
    }
    return result;
}

BlockInfo Node::get_block (std::uint64_t block_height) const
{
    const auto &chain_ids = impl_->best_chain_ids();
    if (block_height >= chain_ids.size())
        throw std::out_of_range("Block height is above the active chain");
    return impl_->make_info(impl_->entries.at(chain_ids[static_cast<std::size_t>(block_height)]));
}

BlockInfo Node::get_block (const Digest &id) const
{
    const auto found = impl_->entries.find(id);
    if (found == impl_->entries.end())
        throw std::out_of_range("Unknown block ID");
    return impl_->make_info(found->second);
}

std::optional<transaction::Transaction> Node::get_transaction (const Digest &txid) const
{
    if (const auto tx = impl_->active_transaction(txid))
        return impl_->historical_block(impl_->entries.at(tx->first)).transactions.at(tx->second);
    for (const auto &entry : impl_->mempool)
        if (entry.txid == txid)
            return entry.tx;
    return std::nullopt;
}

std::string Node::submit (shake::Bytes serialized_transaction)
{
    return impl_->submit_tx(serialized_transaction);
}

std::vector<Digest> Node::mempool_txids () const
{
    std::vector<Digest> result;
    for (const auto &entry : impl_->mempool) result.push_back(entry.txid);
    return result;
}

Block Node::block_template (const AddressPayload &miner) const
{
    std::vector<std::size_t> included, commitments;
    return impl_->make_candidate(impl_->active_tip(), miner, included, commitments);
}

std::vector<BlockInfo> Node::mine (std::uint64_t count, const AddressPayload &miner,
                                   std::uint32_t workers)
{
    std::vector<BlockInfo> mined;
    if (count > static_cast<std::uint64_t>(mined.max_size()))
        throw std::length_error("Requested mining count is too large");
    mined.reserve(static_cast<std::size_t>(count));
    for (std::uint64_t i = 0; i < count; ++i)
        mined.push_back(impl_->mine_one(impl_->best, miner, workers, std::nullopt));
    return mined;
}

BlockInfo Node::mine_on (const Digest &parent, const AddressPayload &miner,
                         std::uint32_t workers, std::optional<std::uint64_t> time)
{
    return impl_->mine_one(parent, miner, workers, time);
}

BlockInfo Node::accept (const Block &block, std::uint64_t adjusted_time)
{
    const auto previous = impl_->best;
    const auto result = impl_->accept_internal(block, adjusted_time, true);
    if (impl_->best != previous)
    {
        // Revalidate pending spends after extensions/reorgs and resurrect ordinary
        // transactions disconnected from the previous active branch.
        auto pending = std::move(impl_->mempool);
        impl_->mempool.clear();
        impl_->mempool_spends.clear();
        for (const auto &entry : pending)
        {
            try { (void)impl_->submit_tx(entry.raw, false, {}, false, &entry.commit_event); }
            catch (const std::exception &) { impl_->erase_pending(entry.txid); }
        }
        auto old = previous;
        std::set<Digest> active;
        for (const auto &id : impl_->best_chain_ids()) active.insert(id);
        while (!active.contains(old))
        {
            const auto &entry = impl_->entries.at(old);
            const auto block = impl_->historical_block(entry);
            for (std::size_t i = 1; i < block.transactions.size(); ++i)
            {
                try { (void)impl_->submit_tx(transaction::serialize(block.transactions[i]), true, {}, false); }
                catch (const std::exception &) { /* Conflicting/non-final disconnected spend. */ }
            }
            old = entry.parent;
        }
    }
    return result;
}

std::vector<std::uint8_t> encode_record (const Block &block) { return store_record(block); }

std::filesystem::path default_data_directory ()
{
    const auto *home = std::getenv("HOME");
    if (!home || !*home) throw std::runtime_error("HOME is unset; pass --datadir DIR");
#ifdef __APPLE__
    const auto directory = std::filesystem::path(home) / "Library/Application Support/E46Tessera";
    const std::vector<std::filesystem::path> legacy{std::filesystem::path(home) / "Library/Caches/E46Tessera"};
#else
    const auto *xdg = std::getenv("XDG_DATA_HOME");
    const auto directory = (xdg && *xdg ? std::filesystem::path(xdg)
        : std::filesystem::path(home) / ".local/share") / "E46Tessera";
    std::vector<std::filesystem::path> legacy{std::filesystem::path(home) / ".cache/E46Tessera"};
    const auto *old_xdg = std::getenv("XDG_CACHE_HOME");
    if (old_xdg && *old_xdg) legacy.emplace_back(std::filesystem::path(old_xdg) / "E46Tessera");
#endif
    if (!std::filesystem::exists(directory / "blocks"))
        for (const auto &old : legacy)
            if (std::filesystem::is_directory(old / "blocks"))
                throw std::runtime_error("Legacy block store found at \"" + old.string()
                    + "\"; new default \"" + directory.string() + "\" has no blocks/. Refusing to start. "
                    "Use --datadir \"" + old.string() + "\", or stop the node and move the old datadir "
                    "yourself to \"" + directory.string() + "\". Nothing was moved or deleted.");
    return directory;
}

bool Node::has_block (const Digest &id) const { return impl_->entries.contains(id); }
std::string Node::submit_relay (shake::Bytes raw, const Digest &id)
{
    return impl_->submit_tx(raw, true, hex(id), false);
}
std::vector<std::uint8_t> Node::block_record (const Digest &id) const
{
    const auto &entry = impl_->entries.at(id);
    if (entry.invalid) throw std::invalid_argument("Block is known invalid");
    return entry.raw;
}
BlockInfo Node::import_record (shake::Bytes raw)
{
    const auto previous = impl_->best;
    const auto result = impl_->accept_record(raw, now_seconds(), true);
    if (impl_->best != previous)
    {
        // Revalidate pending spends after extensions/reorgs and resurrect ordinary
        // transactions disconnected from the previous active branch.
        auto pending = std::move(impl_->mempool);
        impl_->mempool.clear();
        impl_->mempool_spends.clear();
        for (const auto &entry : pending)
        {
            try { (void)impl_->submit_tx(entry.raw, false, {}, false, &entry.commit_event); }
            catch (const std::exception &) { impl_->erase_pending(entry.txid); }
        }
        auto old = previous;
        std::set<Digest> active;
        for (const auto &id : impl_->best_chain_ids()) active.insert(id);
        while (!active.contains(old))
        {
            const auto &entry = impl_->entries.at(old);
            const auto block = impl_->historical_block(entry);
            for (std::size_t i = 1; i < block.transactions.size(); ++i)
            {
                try { (void)impl_->submit_tx(transaction::serialize(block.transactions[i]), true, {}, false); }
                catch (const std::exception &) { /* Conflicting/non-final disconnected spend. */ }
            }
            old = entry.parent;
        }
    }
    return result;
}

void Node::check_peer_block (shake::Bytes raw) const
{
    if (raw.size() < 8 + rl::header_bytes)
        throw std::invalid_argument("Truncated block record");
    const auto header = chain::deserialize_header(raw.subspan(8, rl::header_bytes));
    Digest parent{};
    std::copy(header.prev_block.begin(), header.prev_block.end(), parent.begin());
    const auto found = impl_->entries.find(parent);
    if (found == impl_->entries.end() || parent == impl_->best)
        return;  // unknown parents are rejected by acceptance; tip extensions are always welcome
    const auto height = found->second.height + 1;
    const auto active_height = impl_->active_tip().height;
    for (const auto &checkpoint : checkpoints::testnet())
        if (active_height >= checkpoint.height && height <= checkpoint.height)
            throw std::invalid_argument("Side branch below the block-" + std::to_string(checkpoint.height) +
                                        " checkpoint can never become active");
    if (impl_->entries.size() - impl_->best_chain_ids().size() >= side_branch_budget)
        throw std::invalid_argument("Side-branch storage budget reached (" + std::to_string(side_branch_budget) + " blocks)");
}

std::vector<Digest> Node::locator (std::optional<Digest> cursor) const
{
    auto current = cursor && has_block(*cursor) ? *cursor : tip_id();
    std::vector<Digest> result;
    std::uint64_t stride = 1;
    while (true)
    {
        result.push_back(current);
        if (impl_->entries.at(current).height == 0) break;
        for (std::uint64_t j = 0; j < stride && impl_->entries.at(current).height != 0; ++j)
            current = impl_->entries.at(current).parent;
        if (result.size() > 10 && stride < (std::uint64_t{1} << 62)) stride *= 2;
    }
    return result;
}
std::optional<Digest> Node::next_after (std::span<const Digest> locator) const
{
    const auto &ids = impl_->best_chain_ids();
    for (const auto &id : locator)
    {
        const auto entry = impl_->entries.find(id);
        if (entry == impl_->entries.end()) continue;
        const auto height = entry->second.height;
        if (height >= ids.size() || ids[height] != id) continue;
        if (height + 1 == ids.size()) return {};
        return ids[height + 1];
    }
    throw std::invalid_argument("Locator has no common ancestor");
}
bool Node::solve (Block &block, std::stop_token stop)
{
    const auto target = chain::compact_to_target(block.header.bits);
    for (std::uint64_t nonce = 0; !stop.stop_requested(); ++nonce)
    {
        block.header.nonce = nonce;
        if (rl::rl_v3_header_pow(chain::serialize_header(block.header), target)) return true;
        if (nonce == UINT64_MAX) break;
    }
    return false;
}

} // namespace e46::node
