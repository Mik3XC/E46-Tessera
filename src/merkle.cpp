#include "e46/merkle.hpp"
#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>

namespace e46::merkle
{
Digest leaf_hash (Bytes body)
{
    auto hasher = shake::Shake256::tagged("E46-merkle");
    constexpr std::array<std::uint8_t, 1> prefix{0};
    hasher.update(prefix);
    hasher.update(body);
    const auto bytes = hasher.finalize(32);
    Digest out{};
    std::copy(bytes.begin(), bytes.end(), out.begin());
    return out;
}

Digest node_hash (const Digest &left, const Digest &right)
{
    std::array<std::uint8_t, 65> data{1};
    std::copy(left.begin(), left.end(), data.begin() + 1);
    std::copy(right.begin(), right.end(), data.begin() + 33);
    return shake::shake256_tagged_256("E46-merkle", data);
}

Digest bind_root (const Digest &tree_root, std::uint64_t leaf_count)
{
    if (leaf_count == 0)
    {
        return {};
    }
    std::array<std::uint8_t, 41> data{2};
    for (unsigned i = 0; i < 8; ++i)
    {
        data[1 + i] = static_cast<std::uint8_t>(leaf_count >> (8 * i));
    }
    std::copy(tree_root.begin(), tree_root.end(), data.begin() + 9);
    return shake::shake256_tagged_256("E46-merkle", data);
}

Tree::Tree (std::span<const Leaf> leaves) : leaves_(leaves.begin(), leaves.end())
{
    static_assert(std::numeric_limits<std::size_t>::digits <= 64);
    auto &bottom = levels_.emplace_back();
    bottom.reserve(leaves.size());
    for (const auto &leaf : leaves)
    {
        bottom.push_back(leaf_hash(leaf));
    }
    while (levels_.back().size() > 1)
    {
        const auto &current = levels_.back();
        std::vector<Digest> next;
        next.reserve(current.size() / 2 + current.size() % 2);
        for (std::size_t i = 0; i < current.size() / 2; ++i)
        {
            next.push_back(node_hash(current[2 * i], current[2 * i + 1]));
        }
        if (current.size() % 2 != 0)
        {
            next.push_back(current.back());
        }
        levels_.push_back(std::move(next));
    }
}

Digest Tree::root () const
{
    return bind_root(tree_root(), static_cast<std::uint64_t>(size()));
}

Digest Tree::tree_root () const
{
    return levels_.empty() || levels_.back().empty() ? Digest{} : levels_.back().front();
}

std::size_t Tree::size () const
{
    return levels_.empty() ? 0 : levels_.front().size();
}

Proof Tree::proof (std::uint64_t index) const
{
    if (index >= size())
    {
        throw std::invalid_argument("Merkle proof index outside tree");
    }
    Proof out{
        leaves_[static_cast<std::size_t>(index)], index, static_cast<std::uint64_t>(size()), {}};
    for (const auto &level : levels_)
    {
        const auto sibling = index ^ std::uint64_t{1};
        if (sibling < level.size())
        {
            out.siblings.push_back(level[static_cast<std::size_t>(sibling)]);
        }
        index /= 2;
    }
    return out;
}

bool verify (const Digest &expected_root, const Proof &proof)
{
    return verify(expected_root, proof.leaf, proof.index, proof.leaf_count, proof.siblings);
}

bool verify (const Digest &expected_root, Bytes body, std::uint64_t index, std::uint64_t leaf_count,
             std::span<const Digest> siblings)
{
    if (leaf_count == 0 || index >= leaf_count)
    {
        return false;
    }
    // Validate path shape before hashing. ceil(n/2) avoids n+1 overflow.
    std::size_t required = 0;
    for (auto n = leaf_count, i = index; n > 1; n = n / 2 + n % 2, i /= 2)
    {
        required += ((i ^ std::uint64_t{1}) < n) ? 1 : 0;
    }
    if (siblings.size() != required)
    {
        return false;
    }
    auto current = leaf_hash(body);
    std::size_t used = 0;
    for (auto n = leaf_count, i = index; n > 1; n = n / 2 + n % 2, i /= 2)
    {
        if ((i ^ std::uint64_t{1}) < n)
        {
            current = i % 2 != 0 ? node_hash(siblings[used], current)
                                 : node_hash(current, siblings[used]);
            ++used;
        }
    }
    return bind_root(current, leaf_count) == expected_root;
}

Digest merkle_root (std::span<const Digest> txids)
{
    std::vector<Leaf> leaves;
    leaves.reserve(txids.size());
    for (const auto &txid : txids)
    {
        leaves.emplace_back(txid.begin(), txid.end());
    }
    return Tree(leaves).root();
}

namespace
{
void check_type (std::uint8_t type)
{
    if (type != 0x02 && type != 0x03)
    {
        throw std::invalid_argument("Unknown event type");
    }
}
} // namespace

std::vector<Event> sorted_events (std::span<const Event> events)
{
    for (const auto &event : events)
    {
        check_type(event.type);
    }
    std::vector<Event> out(events.begin(), events.end());
    std::sort(out.begin(), out.end(),
              [] (const Event &a, const Event &b)
              {
                  return a.type != b.type ? a.type < b.type : a.id < b.id;
              });
    for (std::size_t i = 1; i < out.size(); ++i)
    {
        if (out[i - 1].type == out[i].type && out[i - 1].id == out[i].id)
        {
            throw std::invalid_argument("Duplicate event type/ID");
        }
    }
    return out;
}

Leaf event_leaf (const Event &event)
{
    check_type(event.type);
    Leaf leaf{event.type};
    leaf.insert(leaf.end(), event.body.begin(), event.body.end());
    return leaf;
}

Tree event_tree (std::span<const Event> events)
{
    const auto ordered = sorted_events(events);
    std::vector<Leaf> leaves;
    leaves.reserve(ordered.size());
    for (const auto &event : ordered)
    {
        leaves.push_back(event_leaf(event));
    }
    return Tree(leaves);
}

Digest event_root (std::span<const Event> events)
{
    return event_tree(events).root();
}
} // namespace e46::merkle
