#include "e46/transaction.hpp"
#include "e46/addresses.hpp"
#include "e46/keys.hpp"
#include "e46/merkle.hpp"
#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>
#include <type_traits>
#include <string>

namespace e46::transaction
{
namespace
{

template <std::size_t N>
bool array_matches (const std::array<std::uint8_t, N> &expected,
                   const std::vector<std::uint8_t> &actual)
{
    return actual.size() == N && std::equal(expected.begin(), expected.end(), actual.begin());
}
constexpr std::size_t maximum_signature_bytes = keys::signature_bytes;
constexpr std::size_t maximum_coinbase_data = 108;

class Reader
{
public:
    explicit Reader (Bytes bytes) : bytes_(bytes) {}

    std::size_t position () const noexcept { return position_; }
    std::size_t remaining () const noexcept { return bytes_.size() - position_; }
    bool empty () const noexcept { return position_ == bytes_.size(); }

    std::uint8_t u8 ()
    {
        require(1);
        return bytes_[position_++];
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
        const auto result = bytes_.subspan(position_, count);
        position_ += count;
        return result;
    }

    std::uint64_t compact_size ()
    {
        const auto prefix = u8();
        if (prefix < 0xfd)
            return prefix;
        if (prefix == 0xfd)
        {
            require(2);
            const auto value = static_cast<std::uint64_t>(u8()) |
                               (static_cast<std::uint64_t>(u8()) << 8);
            if (value < 0xfd)
                throw std::invalid_argument("Non-minimal CompactSize encoding");
            return value;
        }
        if (prefix == 0xfe)
        {
            const auto value = u32();
            if (value <= 0xffff)
                throw std::invalid_argument("Non-minimal CompactSize encoding");
            return value;
        }
        const auto value = u64();
        if (value <= 0xffffffffULL)
            throw std::invalid_argument("Non-minimal CompactSize encoding");
        return value;
    }

    std::vector<std::uint8_t> varbytes (std::size_t maximum)
    {
        const auto size = compact_size();
        if (size > maximum || size > remaining())
            throw std::invalid_argument("varbytes length exceeds input or limit");
        const auto bytes_view = bytes(static_cast<std::size_t>(size));
        return {bytes_view.begin(), bytes_view.end()};
    }

    void require (std::size_t count) const
    {
        if (count > remaining())
            throw std::invalid_argument("Truncated transaction");
    }

private:
    Bytes bytes_;
    std::size_t position_{};
};

void write_u8 (std::vector<std::uint8_t> &out, std::uint8_t value)
{
    out.push_back(value);
}

void write_u32 (std::vector<std::uint8_t> &out, std::uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i)
        out.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
}

void write_u64 (std::vector<std::uint8_t> &out, std::uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i)
        out.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
}

void write_compact_size (std::vector<std::uint8_t> &out, std::uint64_t value)
{
    if (value < 0xfd)
    {
        out.push_back(static_cast<std::uint8_t>(value));
    }
    else if (value <= 0xffff)
    {
        out.push_back(0xfd);
        out.push_back(static_cast<std::uint8_t>(value));
        out.push_back(static_cast<std::uint8_t>(value >> 8));
    }
    else if (value <= 0xffffffffULL)
    {
        out.push_back(0xfe);
        write_u32(out, static_cast<std::uint32_t>(value));
    }
    else
    {
        out.push_back(0xff);
        write_u64(out, value);
    }
}

void write_varbytes (std::vector<std::uint8_t> &out, Bytes bytes)
{
    write_compact_size(out, static_cast<std::uint64_t>(bytes.size()));
    out.insert(out.end(), bytes.begin(), bytes.end());
}

template <std::size_t N>
std::array<std::uint8_t, N> read_array (Reader &reader)
{
    const auto part = reader.bytes(N);
    std::array<std::uint8_t, N> result{};
    std::copy(part.begin(), part.end(), result.begin());
    return result;
}

bool is_null_prevout (const Input &input) noexcept
{
    return input.previous_index == 0xffffffffU &&
           std::all_of(input.previous_txid.begin(), input.previous_txid.end(),
                       [] (std::uint8_t byte) { return byte == 0; });
}

std::uint64_t checked_add_amount (std::uint64_t total, std::uint64_t value)
{
    if (value > max_amount || total > max_amount - value)
        throw std::invalid_argument("Amount or checked sum exceeds MAX_SUPPLY");
    return total + value;
}

void validate_amount_outputs (std::span<const Output> outputs, bool allow_mint)
{
    if (outputs.empty())
        throw std::invalid_argument("Transaction must have at least one output");
    std::uint64_t total = 0;
    for (const auto &output : outputs)
    {
        validate_output(output);
        total = checked_add_amount(total, output.value);
    }
    (void)allow_mint; // The caller applies the input/output comparison when inputs exist.
}

void write_witness (std::vector<std::uint8_t> &out, const Witness &witness)
{
    std::visit([&out] (const auto &item) {
        using T = std::decay_t<decltype(item)>;
        if constexpr (std::is_same_v<T, CoinbaseWitness>)
        {
            if (item.coinbase_data.size() < 8 || item.coinbase_data.size() > maximum_coinbase_data)
                throw std::invalid_argument("Coinbase witness must be 8..108 bytes");
            write_varbytes(out, item.coinbase_data);
        }
        else if constexpr (std::is_same_v<T, SingleOwnerWitness>)
        {
            if (item.signature.size() != maximum_signature_bytes)
                throw std::invalid_argument("SLH-DSA signature must be 7,856 bytes");
            write_varbytes(out, item.public_key);
            write_varbytes(out, item.signature);
        }
        else if constexpr (std::is_same_v<T, SharedWitness>)
        {
            const auto n = item.public_keys.size();
            if (item.threshold == 0 || item.threshold > n || n > 15 || item.signatures.size() != n)
                throw std::invalid_argument("Shared witness requires 1 <= k <= n <= 15");
            if (!std::is_sorted(item.public_keys.begin(), item.public_keys.end()) ||
                std::adjacent_find(item.public_keys.begin(), item.public_keys.end()) != item.public_keys.end())
                throw std::invalid_argument("Shared witness public keys must be sorted and distinct");
            std::size_t nonempty = 0;
            write_u8(out, item.threshold);
            write_u8(out, static_cast<std::uint8_t>(n));
            for (const auto &key : item.public_keys)
                out.insert(out.end(), key.begin(), key.end());
            for (const auto &signature : item.signatures)
            {
                if (!signature.empty() && signature.size() != maximum_signature_bytes)
                    throw std::invalid_argument("Shared witness signature size");
                nonempty += !signature.empty();
                write_varbytes(out, signature);
            }
            if (nonempty != item.threshold)
                throw std::invalid_argument("Shared witness must contain exactly k signatures");
        }
        else if constexpr (std::is_same_v<T, BlockQtlWitness>)
        {
            if (item.signature.size() != maximum_signature_bytes)
                throw std::invalid_argument("SLH-DSA signature must be 7,856 bytes");
            write_varbytes(out, item.public_key);
            write_varbytes(out, item.signature);
            out.insert(out.end(), item.salt.begin(), item.salt.end());
        }
    }, witness);
}

Witness read_witness (Reader &reader, std::uint8_t spent_type)
{
    if (spent_type == 0x00)
    {
        const auto pk = reader.varbytes(32);
        const auto sig = reader.varbytes(maximum_signature_bytes);
        if (pk.size() != 32 || sig.size() != maximum_signature_bytes)
            throw std::invalid_argument("Malformed single-owner witness lengths");
        SingleOwnerWitness witness{};
        std::copy(pk.begin(), pk.end(), witness.public_key.begin());
        witness.signature = sig;
        return witness;
    }
    if (spent_type == 0x01)
    {
        SharedWitness witness{};
        witness.threshold = reader.u8();
        const auto n = reader.u8();
        if (witness.threshold == 0 || witness.threshold > n || n > 15)
            throw std::invalid_argument("Malformed shared witness threshold/count");
        witness.public_keys.reserve(n);
        for (unsigned i = 0; i < n; ++i)
            witness.public_keys.push_back(read_array<32>(reader));
        if (!std::is_sorted(witness.public_keys.begin(), witness.public_keys.end()) ||
            std::adjacent_find(witness.public_keys.begin(), witness.public_keys.end()) != witness.public_keys.end())
            throw std::invalid_argument("Shared witness public keys must be sorted and distinct");
        witness.signatures.reserve(n);
        std::size_t nonempty = 0;
        for (unsigned i = 0; i < n; ++i)
        {
            auto sig = reader.varbytes(maximum_signature_bytes);
            if (!sig.empty() && sig.size() != maximum_signature_bytes)
                throw std::invalid_argument("Malformed shared witness signature length");
            nonempty += !sig.empty();
            witness.signatures.push_back(std::move(sig));
        }
        if (nonempty != witness.threshold)
            throw std::invalid_argument("Shared witness must contain exactly k signatures");
        return witness;
    }
    if (spent_type == 0x04)
    {
        const auto pk = reader.varbytes(32);
        const auto sig = reader.varbytes(maximum_signature_bytes);
        if (pk.size() != 32 || sig.size() != maximum_signature_bytes)
            throw std::invalid_argument("Malformed Block QTL witness lengths");
        BlockQtlWitness witness{};
        std::copy(pk.begin(), pk.end(), witness.public_key.begin());
        witness.signature = sig;
        witness.salt = read_array<32>(reader);
        return witness;
    }
    throw std::invalid_argument("Spent output type has no transaction signature witness");
}

void write_base (std::vector<std::uint8_t> &out, const Transaction &tx)
{
    if (tx.inputs.empty() || tx.inputs.size() > std::numeric_limits<std::uint32_t>::max())
        throw std::invalid_argument("Transaction input count outside sighash index range");
    validate_amount_outputs(tx.outputs, true);
    write_u32(out, tx.version);
    write_compact_size(out, static_cast<std::uint64_t>(tx.inputs.size()));
    for (const auto &input : tx.inputs)
    {
        out.insert(out.end(), input.previous_txid.begin(), input.previous_txid.end());
        write_u32(out, input.previous_index);
        write_u32(out, input.sequence);
    }
    write_compact_size(out, static_cast<std::uint64_t>(tx.outputs.size()));
    for (const auto &output : tx.outputs)
    {
        write_u64(out, output.value);
        write_u8(out, output.type);
        write_varbytes(out, output.payload);
    }
    write_u64(out, tx.lock_time);
}

void validate_witness_for_coin (const Transaction &tx, std::size_t i,
                                const SpentCoin &spent,
                                std::span<const SpentCoin> spent_coins)
{
    const auto message = sighash(tx, static_cast<std::uint32_t>(i), spent_coins);
    if (spent.output.type == 0x00)
    {
        const auto *witness = std::get_if<SingleOwnerWitness>(&tx.witnesses[i]);
        if (!witness || !array_matches(addresses::single_owner_payload(witness->public_key), spent.output.payload) ||
            !keys::verify(witness->public_key, message, witness->signature))
            throw std::invalid_argument("Single-owner witness is invalid");
        return;
    }
    if (spent.output.type == 0x01)
    {
        const auto *witness = std::get_if<SharedWitness>(&tx.witnesses[i]);
        if (!witness || witness->public_keys.size() != witness->signatures.size() ||
            !array_matches(addresses::shared_payload(witness->threshold, witness->public_keys), spent.output.payload))
            throw std::invalid_argument("Shared witness does not match spent output");
        std::size_t verified = 0;
        for (std::size_t j = 0; j < witness->signatures.size(); ++j)
        {
            if (!witness->signatures[j].empty())
            {
                if (!keys::verify(witness->public_keys[j], message, witness->signatures[j]))
                    throw std::invalid_argument("Invalid shared witness signature");
                ++verified;
            }
        }
        if (verified != witness->threshold)
            throw std::invalid_argument("Shared witness has wrong signature count");
        return;
    }
    if (spent.output.type == 0x04)
    {
        const auto *witness = std::get_if<BlockQtlWitness>(&tx.witnesses[i]);
        if (!witness || !array_matches(addresses::single_owner_payload(witness->public_key), spent.output.payload) ||
            !keys::verify(witness->public_key, message, witness->signature))
            throw std::invalid_argument("Block QTL witness is invalid");
        return;
    }
    (void)tx;
    (void)spent_coins;
    throw std::invalid_argument("Spent output cannot be spent by a signature transaction");
}

} // namespace

std::vector<std::uint8_t> encode_compact_size (std::uint64_t value)
{
    std::vector<std::uint8_t> out;
    write_compact_size(out, value);
    return out;
}

bool is_coinbase (const Transaction &tx) noexcept
{
    return tx.inputs.size() == 1 && is_null_prevout(tx.inputs[0]);
}

bool is_standard (const Transaction &tx) noexcept
{
    return std::all_of(tx.outputs.begin(), tx.outputs.end(), [] (const Output &output) {
        if (output.type >= 0x05)
            return false;
        try
        {
            validate_output(output);
            return true;
        }
        catch (...)
        {
            return false;
        }
    });
}

void validate_output (const Output &output)
{
    if (output.value > max_amount)
        throw std::invalid_argument("Output value exceeds MAX_SUPPLY");
    switch (output.type)
    {
    case 0x00:
    case 0x01:
    case 0x04:
        if (output.payload.size() != 32)
            throw std::invalid_argument("Address output payload must be 32 bytes");
        break;
    case 0x02:
        if (output.payload.size() != 40)
            throw std::invalid_argument("Stake-lock payload must be 40 bytes");
        break;
    case 0x03:
        if (output.payload.size() > 80 || output.value != 0)
            throw std::invalid_argument("Data output must be 0-value and at most 80 bytes");
        break;
    default:
        break; // 0x05..0xFF are consensus-valid but non-standard.
    }
}

std::vector<std::uint8_t> serialize_without_witnesses (const Transaction &tx)
{
    std::vector<std::uint8_t> out;
    write_base(out, tx);
    return out;
}

std::vector<std::uint8_t> serialize (const Transaction &tx)
{
    auto out = serialize_without_witnesses(tx);
    if (tx.witnesses.size() != tx.inputs.size())
        throw std::invalid_argument("Transaction must have one witness per input");
    for (const auto &witness : tx.witnesses)
        write_witness(out, witness);
    return out;
}

Transaction deserialize (Bytes bytes, std::span<const SpentCoin> spent_coins)
{
    Reader reader(bytes);
    Transaction tx{};
    tx.version = reader.u32();
    const auto input_count = reader.compact_size();
    if (input_count == 0 || input_count > std::numeric_limits<std::uint32_t>::max() ||
        input_count > reader.remaining() / 40)
        throw std::invalid_argument("Transaction input count is impossible");
    tx.inputs.reserve(static_cast<std::size_t>(input_count));
    for (std::uint64_t i = 0; i < input_count; ++i)
        tx.inputs.push_back({read_array<32>(reader), reader.u32(), reader.u32()});

    const auto output_count = reader.compact_size();
    if (output_count == 0 || output_count > reader.remaining() / 10)
        throw std::invalid_argument("Transaction output count is impossible");
    tx.outputs.reserve(static_cast<std::size_t>(output_count));
    for (std::uint64_t i = 0; i < output_count; ++i)
    {
        Output output{};
        output.value = reader.u64();
        output.type = reader.u8();
        output.payload = reader.varbytes(reader.remaining());
        validate_output(output);
        tx.outputs.push_back(std::move(output));
    }
    tx.lock_time = reader.u64();

    const auto null_inputs = std::count_if(tx.inputs.begin(), tx.inputs.end(), is_null_prevout);
    const bool coinbase = is_coinbase(tx);
    if (null_inputs != 0 && !coinbase)
        throw std::invalid_argument("Coinbase null prevout is only valid as the sole input");
    if (!coinbase && spent_coins.size() != tx.inputs.size())
        throw std::invalid_argument("Spent-output metadata required to parse witnesses");
    tx.witnesses.reserve(tx.inputs.size());
    if (coinbase)
    {
        CoinbaseWitness witness{};
        witness.coinbase_data = reader.varbytes(maximum_coinbase_data);
        if (witness.coinbase_data.size() < 8)
            throw std::invalid_argument("Coinbase witness must include 8-byte extranonce");
        tx.witnesses.emplace_back(std::move(witness));
    }
    else
    {
        for (std::size_t i = 0; i < tx.inputs.size(); ++i)
            tx.witnesses.push_back(read_witness(reader, spent_coins[i].output.type));
    }
    if (!reader.empty())
        throw std::invalid_argument("Trailing bytes after transaction");
    return tx;
}

Digest txid (const Transaction &tx)
{
    const auto bytes = serialize_without_witnesses(tx);
    return addresses::txid(bytes);
}

Digest wtxid (const Transaction &tx)
{
    const auto bytes = serialize(tx);
    return addresses::wtxid(bytes);
}

Digest sighash (const Transaction &tx, std::uint32_t input_index,
                std::span<const SpentCoin> spent_coins)
{
    if (input_index >= tx.inputs.size() || spent_coins.size() != tx.inputs.size())
        throw std::invalid_argument("Sighash requires an in-range input and every spent coin");
    auto data = serialize_without_witnesses(tx);
    write_u32(data, input_index);
    for (const auto &coin : spent_coins)
    {
        validate_output(coin.output);
        write_u64(data, coin.output.value);
        write_u8(data, coin.output.type);
        write_varbytes(data, coin.output.payload);
    }
    return shake::shake256_tagged_256("E46-sighash", data);
}

Digest witness_commitment (std::span<const Digest> wtxids)
{
    if (wtxids.empty())
        throw std::invalid_argument("Witness commitment requires a coinbase transaction");
    std::vector<Digest> leaves(wtxids.begin(), wtxids.end());
    leaves.front() = {};
    return merkle::merkle_root(leaves);
}

bool has_witness_commitment (const Transaction &coinbase, const Digest &commitment)
{
    if (!is_coinbase(coinbase))
        return false;
    const auto matches = std::count_if(coinbase.outputs.begin(), coinbase.outputs.end(),
        [&commitment] (const Output &output) {
            return output.type == 0x03 && output.payload.size() == commitment.size() &&
                   std::equal(output.payload.begin(), output.payload.end(), commitment.begin());
        });
    return matches == 1;
}

void validate_coinbase (const Transaction &tx, std::uint64_t block_height)
{
    if (!is_coinbase(tx) || tx.inputs.size() != 1 || tx.lock_time != block_height ||
        tx.witnesses.size() != 1 || !std::holds_alternative<CoinbaseWitness>(tx.witnesses[0]))
        throw std::invalid_argument("Malformed coinbase or lock_time does not match height");
    const auto &witness = std::get<CoinbaseWitness>(tx.witnesses[0]);
    if (witness.coinbase_data.size() < 8 || witness.coinbase_data.size() > maximum_coinbase_data)
        throw std::invalid_argument("Coinbase witness must be extranonce[8] plus at most 100 bytes");
    validate_amount_outputs(tx.outputs, true);
}

void validate_transaction (const Transaction &tx, std::span<const SpentCoin> spent_coins,
                           std::uint64_t spending_height)
{
    if (tx.inputs.empty() || tx.outputs.empty() || is_coinbase(tx) ||
        std::any_of(tx.inputs.begin(), tx.inputs.end(), is_null_prevout) ||
        tx.witnesses.size() != tx.inputs.size() || spent_coins.size() != tx.inputs.size())
        throw std::invalid_argument("Malformed ordinary transaction shape");

    std::uint64_t input_total = 0;
    for (const auto &coin : spent_coins)
    {
        validate_output(coin.output);
        input_total = checked_add_amount(input_total, coin.output.value);
        if (coin.is_coinbase &&
            (spending_height < coin.creation_height ||
             spending_height - coin.creation_height < coinbase_maturity))
            throw std::invalid_argument("Coinbase output has not matured");
    }
    std::uint64_t output_total = 0;
    for (const auto &output : tx.outputs)
    {
        validate_output(output);
        output_total = checked_add_amount(output_total, output.value);
    }
    if (output_total > input_total)
        throw std::invalid_argument("Transaction outputs exceed inputs");

    for (std::size_t i = 0; i < spent_coins.size(); ++i)
        validate_witness_for_coin(tx, i, spent_coins[i], spent_coins);
}
} // namespace e46::transaction
