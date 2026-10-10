#include "e46/transaction.hpp"
#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace tx = e46::transaction;

namespace
{
std::vector<std::uint8_t> unhex (const std::string &text)
{
    if (text.size() % 2 != 0)
        throw std::invalid_argument("odd-length hex");
    auto nibble = [] (char c) -> unsigned {
        if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<unsigned>(c - 'a' + 10);
        if (c >= 'A' && c <= 'F') return static_cast<unsigned>(c - 'A' + 10);
        throw std::invalid_argument("invalid hex");
    };
    std::vector<std::uint8_t> result(text.size() / 2);
    for (std::size_t i = 0; i < result.size(); ++i)
        result[i] = static_cast<std::uint8_t>((nibble(text[2 * i]) << 4) | nibble(text[2 * i + 1]));
    return result;
}

std::string hex (tx::Bytes bytes)
{
    static constexpr char digits[] = "0123456789abcdef";
    std::string result(bytes.size() * 2, '0');
    for (std::size_t i = 0; i < bytes.size(); ++i)
    {
        result[2 * i] = digits[bytes[i] >> 4];
        result[2 * i + 1] = digits[bytes[i] & 15];
    }
    return result;
}

template <std::size_t N>
std::array<std::uint8_t, N> fixed (const std::string &text)
{
    const auto value = unhex(text);
    if (value.size() != N)
        throw std::invalid_argument("wrong byte length");
    std::array<std::uint8_t, N> result{};
    std::copy(value.begin(), value.end(), result.begin());
    return result;
}

template <class T>
T number (const std::string &text)
{
    T value{};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size())
        throw std::invalid_argument("invalid integer");
    return value;
}

std::vector<tx::SpentCoin> spent_list (const std::string &text)
{
    std::vector<tx::SpentCoin> result;
    if (text == "-")
        return result;
    std::istringstream list(text);
    std::string item;
    while (std::getline(list, item, ';'))
    {
        std::istringstream fields(item);
        std::string type, value, payload, coinbase, height, extra;
        if (!std::getline(fields, type, ':') || !std::getline(fields, value, ':') ||
            !std::getline(fields, payload, ':') || !std::getline(fields, coinbase, ':') ||
            !std::getline(fields, height, ':') || std::getline(fields, extra, ':'))
            throw std::invalid_argument("spent descriptor format");
        tx::Output output{number<std::uint64_t>(value), number<std::uint8_t>(type), unhex(payload)};
        result.push_back({std::move(output), number<unsigned>(coinbase) != 0,
                          number<std::uint64_t>(height)});
    }
    return result;
}

std::string execute (const std::string &line)
{
    std::istringstream in(line);
    std::string command;
    in >> command;
    if (command == "analyze" || command == "validate")
    {
        std::string raw, spent_text, height_text;
        if (!(in >> raw)) throw std::invalid_argument("missing transaction");
        if (command == "validate")
        {
            if (!(in >> height_text >> spent_text))
                throw std::invalid_argument("validate requires height and spent descriptors");
        }
        else if (!(in >> spent_text))
            throw std::invalid_argument("analyze requires spent descriptors");
        std::string extra;
        if (in >> extra) throw std::invalid_argument("extra fields");
        const auto bytes = unhex(raw);
        const auto spent = spent_list(spent_text);
        const auto transaction = tx::deserialize(bytes, spent);
        if (command == "validate")
        {
            if (tx::is_coinbase(transaction))
                tx::validate_coinbase(transaction, number<std::uint64_t>(height_text));
            else
                tx::validate_transaction(transaction, spent, number<std::uint64_t>(height_text));
            return "1";
        }
        const auto canonical = tx::serialize(transaction);
        std::string hashes = "-";
        if (!tx::is_coinbase(transaction))
        {
            hashes.clear();
            for (std::size_t i = 0; i < transaction.inputs.size(); ++i)
            {
                if (i != 0) hashes.push_back(',');
                hashes += hex(tx::sighash(transaction, static_cast<std::uint32_t>(i), spent));
            }
        }
        return hex(canonical) + " " + hex(tx::txid(transaction)) + " " +
               hex(tx::wtxid(transaction)) + " " + hashes + " " +
               (tx::is_standard(transaction) ? "1" : "0");
    }
    if (command == "wcommit")
    {
        std::string digest_list;
        if (!(in >> digest_list)) throw std::invalid_argument("wcommit requires digests");
        std::string extra;
        if (in >> extra) throw std::invalid_argument("extra fields");
        std::vector<tx::Digest> digests;
        std::istringstream list(digest_list);
        std::string item;
        while (std::getline(list, item, ',')) digests.push_back(fixed<32>(item));
        return hex(tx::witness_commitment(digests));
    }
    if (command == "compact")
    {
        std::string value;
        if (!(in >> value)) throw std::invalid_argument("compact requires value");
        std::string extra;
        if (in >> extra) throw std::invalid_argument("extra fields");
        return hex(tx::encode_compact_size(number<std::uint64_t>(value)));
    }
    throw std::invalid_argument("unknown command");
}
} // namespace

int main ()
{
    std::string line;
    while (std::getline(std::cin, line))
    {
        try { std::cout << execute(line) << '\n'; }
        catch (const std::exception &) { std::cout << "ERR\n"; }
    }
}
