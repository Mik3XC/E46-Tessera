#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace e46::keys
{
using Bytes = std::span<const std::uint8_t>;
inline constexpr std::size_t master_seed_bytes = 32;
inline constexpr std::size_t slh_seed_bytes = 48;
inline constexpr std::size_t public_key_bytes = 32;
inline constexpr std::size_t private_key_bytes = 64;
inline constexpr std::size_t signature_bytes = 7'856;

using MasterSeed = std::array<std::uint8_t, master_seed_bytes>;
using SlhSeed = std::array<std::uint8_t, slh_seed_bytes>;
using PublicKey = std::array<std::uint8_t, public_key_bytes>;
using PrivateKey = std::array<std::uint8_t, private_key_bytes>;
using Signature = std::array<std::uint8_t, signature_bytes>;

struct KeyPair
{
    PublicKey public_key{};
    PrivateKey private_key{};
};

// KMAC256(K=master_seed, X="E46-key" || account_u32le || index_u32le,
// S="", L=48 bytes).
SlhSeed derive_seed (Bytes master_seed, std::uint32_t account, std::uint32_t index);

// FIPS 205 deterministic key generation from SK.seed || SK.prf || PK.seed.
// The first call runs a NIST ACVP seeded-keygen known-answer test. On mismatch,
// the call throws; key generation does not proceed.
void startup_self_test ();
KeyPair keypair_from_seed (const SlhSeed &seed);
KeyPair derive_keypair (Bytes master_seed, std::uint32_t account, std::uint32_t index);
#ifdef E46_KEYS_TESTING
// Test seam: use alternate expected KAT outputs to exercise fail-closed behavior.
KeyPair keypair_from_seed_with_expected_kat_for_test (const SlhSeed &seed,
                                                       const PrivateKey &expected_private,
                                                       const PublicKey &expected_public);
#endif

Signature sign (const PrivateKey &private_key, Bytes message, Bytes context = {});
// Deterministic mode is only for conformance tests against NIST KATs.
Signature sign_deterministic_for_test (const PrivateKey &private_key, Bytes message,
                                       Bytes context = {});
bool verify (const PublicKey &public_key, Bytes message, Bytes signature,
             Bytes context = {});
} // namespace e46::keys
