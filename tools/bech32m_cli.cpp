#include "e46/bech32m.hpp"
#include "hex.hpp"
#include <charconv>
#include <iostream>
#include <sstream>

namespace b32 = e46::bech32m;
namespace hex = e46::rl::tool;

std::vector<std::uint8_t> bytes (const std::string &text)
{
    return text == "-" ? std::vector<std::uint8_t>{} : hex::unhex(text);
}

std::string text_bytes (const std::string &text)
{
    const auto value = bytes(text);
    return {value.begin(), value.end()};
}

std::string show (b32::Bytes value)
{
    return value.empty() ? "-" : hex::hex(value);
}

std::string show_text (const std::string &value)
{
    return show({reinterpret_cast<const std::uint8_t *>(value.data()), value.size()});
}

int main ()
{
    std::string line;
    while (std::getline(std::cin, line))
    {
        try
        {
            if (line.size() > 512)
                throw std::invalid_argument("CLI line too long");
            std::istringstream in(line);
            std::string op, value;
            in >> op;
            std::vector<std::string> args;
            while (in >> value)
                args.push_back(value);
            std::string result;
            if (op == "raw_encode" && args.size() == 2)
                result = b32::encode_raw(text_bytes(args[0]), bytes(args[1]));
            else if (op == "raw_decode" && args.size() == 1)
            {
                const auto decoded = b32::decode_raw(text_bytes(args[0]));
                result = show_text(decoded.hrp) + " " + show(decoded.words);
            }
            else if (op == "encode" && args.size() == 3)
            {
                unsigned version = 0;
                const auto &s = args[1];
                const auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), version);
                if (ec != std::errc{} || ptr != s.data() + s.size() || version > 255)
                    throw std::invalid_argument("CLI version");
                result =
                    b32::encode_e46(args[0], static_cast<std::uint8_t>(version), bytes(args[2]));
            }
            else if (op == "decode" && args.size() == 2)
            {
                const auto decoded = b32::decode_e46(text_bytes(args[1]), args[0]);
                result = decoded.hrp + " " + std::to_string(decoded.version) + " " +
                         show(decoded.payload);
            }
            else
                throw std::invalid_argument("CLI operation/arity");
            std::cout << "OK " << result << '\n';
        }
        catch (const std::invalid_argument &)
        {
            std::cout << "ERR\n";
        }
    }
}
