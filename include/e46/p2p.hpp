#pragma once
#include "e46/node.hpp"
#include <functional>

namespace e46::p2p
{
struct Options
{
    std::string listen = "127.0.0.1:19446";
    std::vector<std::string> connect;
    std::size_t max_peers = 8;
};
using Command = std::function<std::string(const std::vector<std::string> &)>;
// Caller owns the exclusive datadir lock for the entire daemon lifetime.
void serve(node::Node &, const std::filesystem::path &, const Options &, const Command &);
// nullopt means no daemon is listening; protocol/timeout errors never fall back.
std::optional<std::string> request(const std::filesystem::path &, const std::vector<std::string> &);
}
