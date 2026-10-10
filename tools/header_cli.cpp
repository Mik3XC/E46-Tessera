#include "e46/header.hpp"
#include "hex.hpp"
#include <algorithm>
#include <charconv>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>

namespace chain = e46::chain;
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

template <std::size_t N> std::array<std::uint8_t, N> fixed (const std::string &text)
{
    const auto bytes = tool::unhex(text);
    if (bytes.size() != N)
        throw std::invalid_argument("wrong fixed-width hexadecimal field");
    std::array<std::uint8_t, N> out{};
    std::copy(bytes.begin(), bytes.end(), out.begin());
    return out;
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
    std::string op;
    in >> op;
    if (op == "ser")
    {
        std::string prev, merkle, event, time, bits, nonce, version;
        if (!(in >> version >> prev >> merkle >> event >> time >> bits >> nonce))
            throw std::invalid_argument("ser needs version, three digests, time, bits and nonce");
        require_end(in);
        chain::Header header{};
        const auto v = number(version);
        if (v > UINT32_MAX)
            throw std::invalid_argument("version out of range");
        header.version = static_cast<std::uint32_t>(v);
        header.prev_block = fixed<32>(prev);
        header.merkle_root = fixed<32>(merkle);
        header.event_root = fixed<32>(event);
        header.time = number(time);
        header.bits = u32(bits);
        header.nonce = number(nonce);
        const auto bytes = chain::serialize_header(header);
        return tool::hex(bytes);
    }
    if (op == "dec")
    {
        std::string raw;
        if (!(in >> raw))
            throw std::invalid_argument("dec needs header hex");
        require_end(in);
        const auto bytes = tool::unhex(raw);
        const auto h = chain::deserialize_header(bytes);
        std::ostringstream out;
        out << h.version << ' ' << h.prev_block.size() << ' ' << tool::hex(h.prev_block) << ' '
            << tool::hex(h.merkle_root) << ' ' << tool::hex(h.event_root) << ' ' << h.time << ' '
            << h.bits << ' ' << h.nonce;
        return out.str();
    }
    if (op == "compact")
    {
        std::string value;
        if (!(in >> value))
            throw std::invalid_argument("compact needs bits");
        require_end(in);
        return tool::hex(chain::compact_to_target(u32(value)));
    }
    if (op == "target")
    {
        std::string value;
        if (!(in >> value))
            throw std::invalid_argument("target needs 32-byte hex");
        require_end(in);
        const auto target = fixed<32>(value);
        std::ostringstream out;
        out << std::hex << std::setw(8) << std::setfill('0') << chain::target_to_compact(target);
        return out.str();
    }
    if (op == "asert")
    {
        std::string bits, ah, apt, ph, pt;
        if (!(in >> bits >> ah >> apt >> ph >> pt))
            throw std::invalid_argument("asert needs anchor bits/height/time and parent height/time");
        require_end(in);
        std::ostringstream out;
        out << std::hex << std::setw(8) << std::setfill('0')
            << chain::asert_bits(u32(bits), number(ah), number(apt), number(ph), number(pt));
        return out.str();
    }
    if (op == "pow")
    {
        std::string raw;
        if (!(in >> raw))
            throw std::invalid_argument("pow needs header hex");
        require_end(in);
        const auto bytes = tool::unhex(raw);
        const auto header = chain::deserialize_header(bytes);
        return chain::check_header_pow(header) ? "1" : "0";
    }
    if (op == "time")
    {
        std::string time, adjusted, count;
        if (!(in >> time >> adjusted >> count))
            throw std::invalid_argument("time needs new time, adjusted time, count and prior times");
        const auto n = number(count);
        if (n > 11)
            throw std::invalid_argument("too many prior times");
        std::array<std::uint64_t, 11> prior{};
        for (std::uint64_t i = 0; i < n; ++i)
        {
            std::string item;
            if (!(in >> item))
                throw std::invalid_argument("missing prior time");
            prior[static_cast<std::size_t>(i)] = number(item);
        }
        require_end(in);
        return chain::check_block_time(number(time), std::span(prior).first(static_cast<std::size_t>(n)),
                                      number(adjusted)) ? "1" : "0";
    }
    throw std::invalid_argument("unknown header command");
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
}
