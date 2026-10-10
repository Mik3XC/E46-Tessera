#include "e46/addresses.hpp"
#include "hex.hpp"
#include <algorithm>
#include <charconv>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace addr = e46::addresses;
namespace tool = e46::rl::tool;

namespace
{
addr::Network network (const std::string &text)
{
    if (text == "mainnet")
        return addr::Network::mainnet;
    if (text == "testnet")
        return addr::Network::testnet;
    throw std::invalid_argument("network must be mainnet or testnet");
}

std::uint64_t number (const std::string &text)
{
    std::uint64_t value{};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size())
        throw std::invalid_argument("invalid unsigned integer");
    return value;
}

std::vector<std::uint8_t> data_hex (const std::string &text)
{
    return text == "-" ? std::vector<std::uint8_t>{} : tool::unhex(text);
}

void require_end (std::istringstream &in)
{
    std::string extra;
    if (in >> extra)
        throw std::invalid_argument("extra command fields");
}

template <std::size_t N> std::array<std::uint8_t, N> fixed (const std::string &text)
{
    const auto bytes = tool::unhex(text);
    if (bytes.size() != N)
        throw std::invalid_argument("wrong fixed-width hexadecimal field");
    std::array<std::uint8_t, N> out{};
    std::copy(bytes.begin(), bytes.end(), out.begin());
    return out;
}

std::string execute (const std::string &line)
{
    std::istringstream in(line);
    std::string command;
    in >> command;
    if (command == "single")
    {
        std::string net, pk;
        if (!(in >> net >> pk))
            throw std::invalid_argument("single requires network and public key");
        require_end(in);
        const auto key = tool::unhex(pk);
        const auto payload = addr::single_owner_payload(key);
        return tool::hex(payload) + " " + addr::single_owner_address(key, network(net));
    }
    if (command == "shared")
    {
        std::string net, k_text, n_text;
        if (!(in >> net >> k_text >> n_text))
            throw std::invalid_argument("shared requires network, k, n and public keys");
        const auto k = number(k_text), n = number(n_text);
        if (n > 15 || k > 15)
            throw std::invalid_argument("shared key count exceeds 15");
        std::vector<addr::PublicKey> keys;
        keys.reserve(static_cast<std::size_t>(n));
        for (std::uint64_t i = 0; i < n; ++i)
        {
            std::string key;
            if (!(in >> key))
                throw std::invalid_argument("missing shared public key");
            keys.push_back(fixed<32>(key));
        }
        require_end(in);
        const auto payload = addr::shared_payload(static_cast<std::uint8_t>(k), keys);
        return tool::hex(payload) + " " +
               addr::shared_address(static_cast<std::uint8_t>(k), keys, network(net));
    }
    if (command == "txid")
    {
        std::string net, bytes;
        if (!(in >> net >> bytes))
            throw std::invalid_argument("txid requires network and serialized transaction bytes");
        require_end(in);
        const auto data = data_hex(bytes);
        const auto id = addr::txid(data);
        return tool::hex(id) + " " + addr::encode_txid(id, network(net));
    }
    if (command == "wtxid")
    {
        std::string bytes;
        if (!(in >> bytes))
            throw std::invalid_argument("wtxid requires full serialized transaction bytes");
        require_end(in);
        return tool::hex(addr::wtxid(data_hex(bytes)));
    }
    if (command == "block")
    {
        std::string net, bytes;
        if (!(in >> net >> bytes))
            throw std::invalid_argument("block requires network and serialized header");
        require_end(in);
        const auto id = addr::block_id(tool::unhex(bytes));
        return tool::hex(id) + " " + addr::encode_block_id(id, network(net));
    }
    if (command == "rad")
    {
        std::string net, previous_text, window_text, nonce_text, miner_text, a_text, b_text;
        if (!(in >> net >> previous_text >> window_text >> nonce_text >> miner_text >> a_text >> b_text))
            throw std::invalid_argument("rad requires network, previous ID, window, nonce, miner, a, b");
        require_end(in);
        const auto previous = fixed<32>(previous_text);
        e46::rad::Rad event{};
        event.window = number(window_text);
        event.nonce = number(nonce_text);
        event.miner = fixed<32>(miner_text);
        event.a = fixed<16>(a_text);
        event.b = fixed<16>(b_text);
        const auto id = addr::rad_id(previous, event);
        return tool::hex(id) + " " + addr::encode_rad_id(id, network(net));
    }
    if (command == "decode")
    {
        std::string kind, net, encoded;
        if (!(in >> kind >> net >> encoded))
            throw std::invalid_argument("decode requires kind, network and Bech32m string");
        require_end(in);
        const auto n = network(net);
        if (kind == "single")
            return tool::hex(addr::decode_single_owner_address(encoded, n));
        if (kind == "shared")
            return tool::hex(addr::decode_shared_address(encoded, n));
        if (kind == "txid")
            return tool::hex(addr::decode_txid(encoded, n));
        if (kind == "block")
            return tool::hex(addr::decode_block_id(encoded, n));
        if (kind == "rad")
            return tool::hex(addr::decode_rad_id(encoded, n));
        throw std::invalid_argument("unknown Bech32m object kind");
    }
    throw std::invalid_argument("unknown addresses_cli command");
}

} // namespace

int main ()
{
    std::string line;
    while (std::getline(std::cin, line))
    {
        try
        {
            auto result = execute(line);
            std::cout << result << '\n';
        }
        catch (const std::exception &error)
        {
            std::cout << "ERR " << error.what() << '\n';
        }
    }
}
