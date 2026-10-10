#include "e46/keys.hpp"
#include <charconv>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace keys = e46::keys;

namespace
{
std::vector<std::uint8_t> unhex (const std::string &text)
{
    if (text.size() % 2 != 0)
        throw std::invalid_argument("odd-length hex");
    auto nibble = [](char c) -> unsigned {
        if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<unsigned>(c - 'a' + 10);
        if (c >= 'A' && c <= 'F') return static_cast<unsigned>(c - 'A' + 10);
        throw std::invalid_argument("invalid hex");
    };
    std::vector<std::uint8_t> out(text.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i)
        out[i] = static_cast<std::uint8_t>((nibble(text[2 * i]) << 4) | nibble(text[2 * i + 1]));
    return out;
}

std::string hex (keys::Bytes bytes)
{
    static constexpr char digits[] = "0123456789abcdef";
    std::string out(bytes.size() * 2, '0');
    for (std::size_t i = 0; i < bytes.size(); ++i)
    {
        out[2 * i] = digits[bytes[i] >> 4];
        out[2 * i + 1] = digits[bytes[i] & 15];
    }
    return out;
}

template <std::size_t N>
std::array<std::uint8_t, N> fixed (const std::string &text)
{
    const auto bytes = unhex(text);
    if (bytes.size() != N)
        throw std::invalid_argument("wrong byte length");
    std::array<std::uint8_t, N> out{};
    std::copy(bytes.begin(), bytes.end(), out.begin());
    return out;
}

std::uint32_t number (const std::string &text)
{
    std::uint32_t value{};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size())
        throw std::invalid_argument("invalid u32");
    return value;
}

void require_end (std::istringstream &in)
{
    std::string extra;
    if (in >> extra) throw std::invalid_argument("extra fields");
}

std::string execute (const std::string &line)
{
    std::istringstream in(line);
    std::string op;
    in >> op;
    if (op == "seed")
    {
        std::string master, account, index;
        if (!(in >> master >> account >> index)) throw std::invalid_argument("seed fields");
        require_end(in);
        const auto m = fixed<keys::master_seed_bytes>(master);
        const auto out = keys::derive_seed(m, number(account), number(index));
        return hex(out);
    }
    if (op == "keygen")
    {
        std::string seed;
        if (!(in >> seed)) throw std::invalid_argument("keygen fields");
        require_end(in);
        const auto pair = keys::keypair_from_seed(fixed<keys::slh_seed_bytes>(seed));
        return hex(pair.public_key) + " " + hex(pair.private_key);
    }
    if (op == "sign" || op == "signdet")
    {
        std::string private_key, message, context;
        if (!(in >> private_key >> message >> context)) throw std::invalid_argument("sign fields");
        require_end(in);
        const auto sk = fixed<keys::private_key_bytes>(private_key);
        const auto m = unhex(message);
        const auto c = context == "-" ? std::vector<std::uint8_t>{} : unhex(context);
        const auto signature = op == "sign" ? keys::sign(sk, m, c)
                                              : keys::sign_deterministic_for_test(sk, m, c);
        return hex(signature);
    }
    if (op == "verify")
    {
        std::string public_key, message, context, signature;
        if (!(in >> public_key >> message >> context >> signature))
            throw std::invalid_argument("verify fields");
        require_end(in);
        const auto pk = fixed<keys::public_key_bytes>(public_key);
        const auto m = unhex(message);
        const auto c = context == "-" ? std::vector<std::uint8_t>{} : unhex(context);
        const auto sig = unhex(signature);
        return keys::verify(pk, m, sig, c) ? "1" : "0";
    }
    throw std::invalid_argument("unknown operation");
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
