#include "e46/checkpoints.hpp"
#include <array>
#include <stdexcept>
#include <string>

namespace e46::checkpoints
{
namespace
{
// First ordinary payment milestone. This explicit early testnet anchor was
// selected by the project owner; it does not replace normal block validation.
// Alternative local chains cannot cross height 268 with a different block ID.
constexpr std::array<Checkpoint, 1> anchors{{
    {268, "4e6bd53958345c17ae9a3f338767e69b7da8a9c8ac361b7ba591eb26506958de"},
}};
} // namespace

std::span<const Checkpoint> testnet () noexcept
{
    return anchors;
}

void validate_testnet (std::uint64_t height, const shake::Digest256 &block_id)
{
    constexpr char digits[] = "0123456789abcdef";
    for (const auto &checkpoint : anchors)
    {
        if (height != checkpoint.height) continue;
        std::string encoded;
        encoded.reserve(block_id.size() * 2);
        for (const auto byte : block_id)
        {
            encoded.push_back(digits[byte >> 4]);
            encoded.push_back(digits[byte & 15]);
        }
        if (encoded != checkpoint.block_id)
            throw std::invalid_argument("Testnet checkpoint mismatch at height " + std::to_string(height));
    }
}
} // namespace e46::checkpoints
