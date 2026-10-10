#pragma once
#include "e46/shake.hpp"
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace e46::merkle
{
using Digest = shake::Digest256;
using Bytes = shake::Bytes;
using Leaf = std::vector<std::uint8_t>;
struct Proof
{
    Leaf leaf;
    std::uint64_t index{};
    std::uint64_t leaf_count{};
    std::vector<Digest> siblings;
};

Digest leaf_hash (Bytes body);
Digest node_hash (const Digest &left, const Digest &right);
// SHAKE256(tag || 0x02 || u64 LE count || raw tree root); zero for count zero.
Digest bind_root (const Digest &tree_root, std::uint64_t leaf_count);

// Owns leaves and hashed levels. Every nonempty root includes the count seal.
class Tree
{
public:
    explicit Tree (std::span<const Leaf> leaves);
    Digest root () const;
    // Diagnostic/intermediate value only. Never use as a chain root.
    Digest tree_root () const;
    std::size_t size () const;
    // Complete proof; siblings bottom up, omitting carried levels.
    // Invalid index throws. No network wire format is defined by this struct.
    Proof proof (std::uint64_t index) const;

private:
    std::vector<std::vector<Digest>> levels_;
    std::vector<Leaf> leaves_;
};

// The caller authenticates expected_root (e.g. from a validated header chain).
// The proof's count is sealed into that root. Rejects zero count, impossible
// positions and extra/missing siblings. SHAKE provider errors propagate.
bool verify (const Digest &expected_root, const Proof &proof);
bool verify (const Digest &expected_root, Bytes body, std::uint64_t index, std::uint64_t leaf_count,
             std::span<const Digest> siblings);

// Transactions preserve supplied block order (coinbase first); no sorting.
Digest merkle_root (std::span<const Digest> txids);

struct Event
{
    std::uint8_t type;
    Leaf id;   // Supplied sort key; NOT added to the serialized leaf.
    Leaf body; // Already serialized body WITHOUT the type byte.
};

// Only envelope type (0x02/0x03) and duplicate (type, ID) are validated here.
// ID lengths/derivation, body encoding, stamp work and Rad validity are the
// caller's responsibility (WO-08/09). Opaque/empty bodies and IDs are supported
// by this primitive, not thereby declared valid chain events.
std::vector<Event> sorted_events (std::span<const Event> events);
Leaf event_leaf (const Event &event); // type || body; no framing or ID inserted
// Proof indices refer to sorted_events(events), not the original input order.
Tree event_tree (std::span<const Event> events);
Digest event_root (std::span<const Event> events);
} // namespace e46::merkle
