#include "e46/genesis.hpp"
#include "hex.hpp"
#include <charconv>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

namespace gen = e46::genesis;
namespace tool = e46::rl::tool;

namespace
{
std::uint64_t number (const std::string &text)
{
    std::uint64_t value{};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size())
        throw std::invalid_argument("invalid unsigned integer");
    return value;
}

std::uint32_t u32 (const std::string &text)
{
    const auto value = number(text);
    if (value > UINT32_MAX)
        throw std::invalid_argument("u32 out of range");
    return static_cast<std::uint32_t>(value);
}

std::uint32_t bits (const std::string &text)
{
    std::size_t consumed = 0;
    const auto value = std::stoull(text, &consumed, 0);
    if (consumed != text.size() || value > UINT32_MAX)
        throw std::invalid_argument("invalid compact bits");
    return static_cast<std::uint32_t>(value);
}

void require_end (std::istringstream &in)
{
    std::string extra;
    if (in >> extra)
        throw std::invalid_argument("extra command fields");
}

std::string execute (const std::string &line)
{
    std::istringstream in(line);
    std::string op, network, timestamp_hex, split_text, time_text, bits_text, fifth, sixth;
    if (!(in >> op >> network >> timestamp_hex >> split_text >> time_text >> bits_text))
        throw std::invalid_argument("expected operation, network, timestamp hex, split, time, bits");
    if (network != "mainnet" && network != "testnet")
        throw std::invalid_argument("network must be mainnet or testnet");
    const auto timestamp = tool::unhex(timestamp_hex);
    const auto split = static_cast<std::size_t>(number(split_text));
    const auto time = number(time_text);
    const auto target_bits = bits(bits_text);
    gen::Block block{};
    if (op == "build")
    {
        if (!(in >> fifth))
            throw std::invalid_argument("build needs nonce");
        require_end(in);
        block = gen::build(timestamp, time, target_bits, number(fifth), split);
    }
    else if (op == "mine")
    {
        if (!(in >> fifth >> sixth))
            throw std::invalid_argument("mine needs worker count and maximum nonce");
        require_end(in);
        block = gen::mine(timestamp, time, target_bits, u32(fifth), number(sixth), split);
    }
    else
    {
        throw std::invalid_argument("unknown genesis operation");
    }
    return network + " " + timestamp_hex + " " + tool::hex(block.serialized_coinbase) + " " +
           tool::hex(block.coinbase_txid) + " " + tool::hex(block.coinbase_wtxid) + " " +
           tool::hex(block.witness_commitment) + " " + tool::hex(block.header.merkle_root) + " " +
           tool::hex(block.serialized_header) + " " + tool::hex(block.block_id) + " " +
           (block.pow_valid ? "1" : "0") + " " + std::to_string(block.header.nonce);
}
} // namespace

int main ()
{
    std::string line;
    while (std::getline(std::cin, line))
    {
        try
        {
            std::cout << execute(line) << '\n';
        }
        catch (const std::exception &)
        {
            std::cout << "ERR\n";
        }
    }
    return 0;
}
