#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

// WO-02: SHAKE256 (FIPS 202) and KMAC256 (NIST SP 800-185) via OpenSSL 3.
// E46 never implements these itself; this is a thin, checked wrapper.
namespace e46::shake
{
using Bytes = std::span<const std::uint8_t>;
using Digest256 = std::array<std::uint8_t, 32>;

// Output-length policy for this wrapper (bytes). E46 uses 16, 32 and 64.
inline constexpr std::size_t max_output_bytes = 1u << 20;

// KMAC256 limits enforced before calling OpenSSL (OpenSSL's own bounds).
inline constexpr std::size_t kmac_min_key_bytes = 4;
inline constexpr std::size_t kmac_max_key_bytes = 512;
inline constexpr std::size_t kmac_max_custom_bytes = 512;
inline constexpr std::size_t kmac_max_output_bytes = 0xFFFFFF / 8;

// SHAKE256(data), out_len bytes (0 gives an empty result).
std::vector<std::uint8_t> shake256 (Bytes data, std::size_t out_len);
Digest256 shake256_256 (Bytes data);

// E46 domain separation: SHAKE256(ASCII(tag) || 0x00 || data).
// tag must be non-empty printable ASCII without NUL, e.g. "E46-txid".
std::vector<std::uint8_t> shake256_tagged (std::string_view tag, Bytes data, std::size_t out_len);
Digest256 shake256_tagged_256 (std::string_view tag, Bytes data);

// Incremental SHAKE256. finalize() may be called once; update() after it throws.
class Shake256
{
public:
    Shake256 ();
    static Shake256 tagged (std::string_view tag);
    Shake256 (Shake256 &&) noexcept;
    Shake256 &operator=(Shake256 &&) noexcept;
    Shake256 (const Shake256 &) = delete;
    Shake256 &operator=(const Shake256 &) = delete;
    ~Shake256 ();

    void update (Bytes data);
    std::vector<std::uint8_t> finalize (std::size_t out_len);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// KMAC256(key, data, out_len, customization) with the output length bound into
// the MAC (non-XOF mode), as SP 800-185 specifies.
std::vector<std::uint8_t> kmac256 (Bytes key, Bytes data, std::size_t out_len,
                                   std::string_view customization = {});
} // namespace e46::shake
