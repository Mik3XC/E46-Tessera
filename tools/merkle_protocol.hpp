#pragma once
#include "e46/merkle.hpp"
#include "hex.hpp"
#include <algorithm>
#include <charconv>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>

// Test-tool text protocol only; not a consensus/network serialization.
namespace e46::merkle::tool
{
inline std::uint64_t number (std::string_view text)
{
    std::uint64_t out{};
    const auto result = std::from_chars(text.data(), text.data() + text.size(), out);
    if (text.empty() || result.ec != std::errc{} || result.ptr != text.data() + text.size())
    {
        throw std::invalid_argument("Expected unsigned decimal");
    }
    return out;
}

inline Leaf bytes (std::string_view text)
{
    return rl::tool::unhex(text == "-" ? "" : text);
}

inline Digest digest (std::string_view text)
{
    const auto decoded = bytes(text);
    if (decoded.size() != 32)
    {
        throw std::invalid_argument("Expected 32-byte digest");
    }
    Digest out{};
    std::copy(decoded.begin(), decoded.end(), out.begin());
    return out;
}

inline Event event (std::string_view text)
{
    const auto first = text.find(':');
    const auto second = first == text.npos ? text.npos : text.find(':', first + 1);
    if (second == text.npos || text.find(':', second + 1) != text.npos)
    {
        throw std::invalid_argument("Expected type:id:body");
    }
    const auto type = number(text.substr(0, first));
    if (type > 255)
    {
        throw std::invalid_argument("Type overflow");
    }
    return Event{static_cast<std::uint8_t>(type), bytes(text.substr(first + 1, second - first - 1)),
                 bytes(text.substr(second + 1))};
}

inline std::string path_text (const Proof &path)
{
    const auto leaf = path.leaf.empty() ? "-" : rl::tool::hex(path.leaf);
    std::string out =
        "OK " + leaf + " " + std::to_string(path.index) + " " + std::to_string(path.leaf_count);
    for (const auto &sibling : path.siblings)
    {
        out += " " + rl::tool::hex(sibling);
    }
    return out;
}

inline std::string dispatch (const std::string &line)
{
    // Tool limits bound fuzz/test allocations; library has no block-size policy.
    if (line.size() > 2 * 1024 * 1024)
    {
        throw std::invalid_argument("Tool line limit");
    }
    std::istringstream input(line);
    std::vector<std::string> words;
    for (std::string word; input >> word;)
    {
        if (words.size() >= 4102)
        {
            throw std::invalid_argument("Tool token limit");
        }
        words.push_back(std::move(word));
    }
    if (words.empty())
    {
        throw std::invalid_argument("Missing operation");
    }
    const auto &op = words[0];
    if (op == "verify")
    {
        if (words.size() < 5)
        {
            throw std::invalid_argument("Missing verify fields");
        }
        Proof proof{bytes(words[2]), number(words[3]), number(words[4]), {}};
        for (std::size_t i = 5; i < words.size(); ++i)
        {
            proof.siblings.push_back(digest(words[i]));
        }
        const bool valid = verify(digest(words[1]), proof);
        return valid ? "OK 1" : "OK 0";
    }
    if (op == "bind")
    {
        if (words.size() != 3)
        {
            throw std::invalid_argument("Expected count and raw root");
        }
        return "OK " + rl::tool::hex(bind_root(digest(words[2]), number(words[1])));
    }
    const bool is_proof = op == "proof" || op == "event_proof";
    if (is_proof && words.size() < 2)
    {
        throw std::invalid_argument("Missing index");
    }
    const std::size_t first = is_proof ? 2 : 1;
    const auto index = is_proof ? number(words[1]) : 0;
    if (op == "events" || op == "event_root" || op == "event_proof")
    {
        std::vector<Event> events;
        for (std::size_t i = first; i < words.size(); ++i)
        {
            events.push_back(event(words[i]));
        }
        if (op == "events")
        {
            std::string out = "OK";
            for (const auto &entry : sorted_events(events))
            {
                out += " " + rl::tool::hex(event_leaf(entry));
            }
            return out;
        }
        const auto tree = event_tree(events);
        return is_proof ? path_text(tree.proof(index)) : "OK " + rl::tool::hex(tree.root());
    }
    if (op == "txroot")
    {
        std::vector<Digest> txids;
        for (std::size_t i = first; i < words.size(); ++i)
        {
            txids.push_back(digest(words[i]));
        }
        return "OK " + rl::tool::hex(merkle_root(txids));
    }
    if (op == "root" || op == "proof" || op == "tree_root")
    {
        std::vector<Leaf> leaves;
        for (std::size_t i = first; i < words.size(); ++i)
        {
            leaves.push_back(bytes(words[i]));
        }
        const Tree tree(leaves);
        return is_proof ? path_text(tree.proof(index))
                        : "OK " + rl::tool::hex(op == "tree_root" ? tree.tree_root() : tree.root());
    }
    throw std::invalid_argument("Unknown operation");
}
} // namespace e46::merkle::tool
