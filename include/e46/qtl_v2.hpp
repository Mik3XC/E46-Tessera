#pragma once
#include "e46/shake.hpp"
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace e46::qtl_v2
{
using Bytes = shake::Bytes;

// QTL v2 research primitives. Inputs are the exact framed bytes used by the
// Python reference; callers keep the envelope fingerprint outside the envelope.
inline constexpr std::string_view format = "E46-QTL-2";
std::vector<std::uint8_t> fingerprint (Bytes canonical_envelope);
std::vector<std::uint8_t> checkpoint_commit (char lock, std::uint32_t index, Bytes state);
std::vector<std::uint8_t> chain_step (Bytes state);
std::vector<std::uint8_t> lock_a_advance (Bytes state, Bytes modulus, std::uint32_t squarings);
std::vector<std::uint8_t> lock_b_advance (Bytes state, std::uint32_t steps);
std::vector<std::uint8_t> password_check (Bytes password_key, Bytes salt);
std::vector<std::uint8_t> final_key (Bytes password_key, Bytes y_a_be, Bytes y_b);
std::vector<std::uint8_t> aes256gcm_encrypt (Bytes key, Bytes nonce, Bytes plaintext, Bytes aad);
std::vector<std::uint8_t> aes256gcm_decrypt (Bytes key, Bytes nonce, Bytes ciphertext_and_tag, Bytes aad);
std::vector<std::uint8_t> argon2id (Bytes credential, Bytes salt,
                                    std::uint32_t memory_kib, std::uint32_t passes,
                                    std::uint32_t parallelism);
} // namespace e46::qtl_v2
