#include "e46/rad.hpp"
#include "hex.hpp"
#include <algorithm>
#include <charconv>
#include <iostream>
#include <sstream>
using namespace e46;
using rl::tool::hex;
using rl::tool::unhex;
namespace
{
std::uint64_t number (const std::string &s)
{
    std::uint64_t n{};
    auto [end, error] = std::from_chars(s.data(), s.data() + s.size(), n);
    if (error != std::errc{} || end != s.data() + s.size())
        throw std::invalid_argument("integer");
    return n;
}
rad::Payload payload (const std::string &s)
{
    auto b = unhex(s);
    if (b.size() != 32)
        throw std::invalid_argument("payload");
    rad::Payload out{};
    std::copy(b.begin(), b.end(), out.begin());
    return out;
}
} // namespace
int main ()
{
    std::string line;
    while (std::getline(std::cin, line))
    {
        try
        {
            std::istringstream stream(line);
            std::vector<std::string> a;
            for (std::string s; stream >> s;)
                a.push_back(s);
            if (a.size() == 6 && a[0] == "event")
            {
                auto z = number(a[4]);
                if (z > 128)
                    throw std::invalid_argument("Z");
                rad::Context context{payload(a[1]), number(a[2])};
                rad::Policy policy{number(a[3]), static_cast<unsigned>(z)};
                auto r = rad::decode(unhex(a[5]));
                auto s = rad::stamp({context.previous, r.window}, r.miner, r.nonce);
                auto valid = rad::verify(context, policy, r);
                std::cout << hex(s) << ' ' << hex(rad::candidate_hash(s, r.a)) << ' '
                          << hex(rad::candidate_hash(s, r.b)) << ' ' << hex(rad::id(context, r))
                          << ' ' << hex(rad::encode(r)) << ' ' << valid;
                if (valid)
                {
                    auto e = rad::checked_event(context, policy, r);
                    auto tree = merkle::event_tree(std::span(&e, 1));
                    if (!merkle::verify(tree.root(), tree.proof(0)))
                        throw std::runtime_error("proof");
                    std::cout << ' ' << hex(tree.root());
                }
                std::cout << '\n';
            }
            else if (a.size() == 4 && a[0] == "commit")
            {
                auto z = number(a[3]);
                if (z > 128)
                    throw std::invalid_argument("Z");
                auto c = payload(a[1]);
                auto n = number(a[2]);
                std::cout << hex(rad::commit_hash(c, n)) << ' '
                          << rad::commit_valid(c, n, static_cast<unsigned>(z)) << '\n';
            }
            else if (a.size() == 2 && a[0] == "tier")
            {
                auto z = number(a[1]);
                if (z > 128)
                    throw std::invalid_argument("Z");
                std::cout << rad::collision_tier(static_cast<unsigned>(z)) << '\n';
            }
            else
                throw std::invalid_argument("command");
        }
        catch (const std::exception &)
        {
            std::cout << "ERR\n";
        }
    }
}
