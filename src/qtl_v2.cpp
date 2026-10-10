#include "e46/qtl_v2.hpp"
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <array>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

namespace e46::qtl_v2
{
namespace
{
struct KdfFree { void operator()(EVP_KDF *p) const noexcept { EVP_KDF_free(p); } };
struct KdfCtxFree { void operator()(EVP_KDF_CTX *p) const noexcept { EVP_KDF_CTX_free(p); } };
struct MdCtxFree { void operator()(EVP_MD_CTX *p) const noexcept { EVP_MD_CTX_free(p); } };
struct BnFree { void operator()(BIGNUM *p) const noexcept { BN_clear_free(p); } };
struct BnCtxFree { void operator()(BN_CTX *p) const noexcept { BN_CTX_free(p); } };
struct CipherCtxFree { void operator()(EVP_CIPHER_CTX *p) const noexcept { EVP_CIPHER_CTX_free(p); } };

std::vector<std::uint8_t> tagged (std::string_view tag, Bytes data, std::size_t n)
{
    return shake::shake256_tagged(tag, data, n);
}

void append_u32_be (std::vector<std::uint8_t> &out, std::uint32_t value)
{
    out.push_back(static_cast<std::uint8_t>(value >> 24));
    out.push_back(static_cast<std::uint8_t>(value >> 16));
    out.push_back(static_cast<std::uint8_t>(value >> 8));
    out.push_back(static_cast<std::uint8_t>(value));
}
} // namespace

std::vector<std::uint8_t> fingerprint (Bytes canonical_envelope)
{
    return tagged("E46-QTL-2-fingerprint", canonical_envelope, 32);
}

std::vector<std::uint8_t> checkpoint_commit (char lock, std::uint32_t index, Bytes state)
{
    if (lock != 'A' && lock != 'B')
        throw std::invalid_argument("QTL checkpoint lock must be A or B");
    if (state.size() > UINT32_MAX)
        throw std::invalid_argument("QTL checkpoint state too large");
    std::vector<std::uint8_t> frame;
    frame.reserve(9 + state.size());
    frame.push_back(static_cast<std::uint8_t>(lock));
    append_u32_be(frame, index);
    append_u32_be(frame, static_cast<std::uint32_t>(state.size()));
    frame.insert(frame.end(), state.begin(), state.end());
    return tagged("E46-QTL-2-checkpoint", frame, 16);
}

std::vector<std::uint8_t> chain_step (Bytes state)
{
    return tagged("E46-QTL-2-lock-b", state, 32);
}

std::vector<std::uint8_t> lock_a_advance (Bytes state, Bytes modulus, std::uint32_t squarings)
{
    if (state.empty() || modulus.empty() || state.size() > INT_MAX || modulus.size() > INT_MAX)
        throw std::invalid_argument("invalid QTL Lock-A integer width");
    std::unique_ptr<BIGNUM, BnFree> x(BN_bin2bn(state.data(), static_cast<int>(state.size()), nullptr));
    std::unique_ptr<BIGNUM, BnFree> n(BN_bin2bn(modulus.data(), static_cast<int>(modulus.size()), nullptr));
    std::unique_ptr<BIGNUM, BnFree> y(BN_new());
    std::unique_ptr<BN_CTX, BnCtxFree> ctx(BN_CTX_new());
    if (!x || !n || !y || !ctx || BN_is_zero(n.get()) || BN_is_negative(n.get()) || BN_cmp(x.get(), n.get()) >= 0)
        throw std::invalid_argument("invalid QTL Lock-A state or modulus");
    for (std::uint32_t i = 0; i < squarings; ++i)
        if (BN_mod_sqr(y.get(), x.get(), n.get(), ctx.get()) != 1 || BN_copy(x.get(), y.get()) == nullptr)
            throw std::runtime_error("OpenSSL Lock-A modular squaring failed");
    std::vector<std::uint8_t> out(modulus.size());
    if (BN_bn2binpad(x.get(), out.data(), static_cast<int>(out.size())) != static_cast<int>(out.size()))
        throw std::runtime_error("OpenSSL Lock-A result encoding failed");
    return out;
}

std::vector<std::uint8_t> lock_b_advance (Bytes state, std::uint32_t steps)
{
    if (state.size() != 32)
        throw std::invalid_argument("QTL Lock-B state must be 32 bytes");
    std::vector<std::uint8_t> current(state.begin(), state.end());
    for (std::uint32_t i = 0; i < steps; ++i)
    {
        auto next = chain_step(current);
        OPENSSL_cleanse(current.data(), current.size());
        current = std::move(next);
    }
    return current;
}

std::vector<std::uint8_t> password_check (Bytes password_key, Bytes salt)
{
    return shake::kmac256(password_key, salt, 16, "E46-QTL-2 password-check");
}

std::vector<std::uint8_t> final_key (Bytes password_key, Bytes y_a_be, Bytes y_b)
{
    if (y_b.size() != 32)
        throw std::invalid_argument("QTL Lock-B result must be 32 bytes");
    std::vector<std::uint8_t> material;
    material.reserve(y_a_be.size() + y_b.size());
    material.insert(material.end(), y_a_be.begin(), y_a_be.end());
    material.insert(material.end(), y_b.begin(), y_b.end());
    auto out = shake::kmac256(password_key, material, 32, format);
    OPENSSL_cleanse(material.data(), material.size());
    return out;
}

std::vector<std::uint8_t> aes256gcm_encrypt (Bytes key, Bytes nonce, Bytes plaintext, Bytes aad)
{
    if (key.size() != 32 || nonce.empty() || nonce.size() > INT_MAX || plaintext.size() > INT_MAX || aad.size() > INT_MAX)
        throw std::invalid_argument("invalid AES-256-GCM key, nonce, or input length");
    std::unique_ptr<EVP_CIPHER_CTX, CipherCtxFree> ctx(EVP_CIPHER_CTX_new());
    if (!ctx || EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1)
        throw std::runtime_error("OpenSSL AES-256-GCM initialization failed");
    int n = 0;
    if (!aad.empty() && EVP_EncryptUpdate(ctx.get(), nullptr, &n, aad.data(), static_cast<int>(aad.size())) != 1)
        throw std::runtime_error("OpenSSL AES-GCM AAD failed");
    std::vector<std::uint8_t> out(plaintext.size() + 16);
    int written = 0;
    if (!plaintext.empty() && EVP_EncryptUpdate(ctx.get(), out.data(), &written, plaintext.data(), static_cast<int>(plaintext.size())) != 1)
        throw std::runtime_error("OpenSSL AES-GCM encryption failed");
    int tail = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), out.data() + written, &tail) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, out.data() + plaintext.size()) != 1)
        throw std::runtime_error("OpenSSL AES-GCM finalization failed");
    out.resize(plaintext.size() + 16);
    return out;
}

std::vector<std::uint8_t> aes256gcm_decrypt (Bytes key, Bytes nonce, Bytes ciphertext_and_tag, Bytes aad)
{
    if (key.size() != 32 || nonce.empty() || nonce.size() > INT_MAX || ciphertext_and_tag.size() < 16 ||
        ciphertext_and_tag.size() - 16 > INT_MAX || aad.size() > INT_MAX)
        throw std::invalid_argument("invalid AES-256-GCM key, nonce, ciphertext, or input length");
    std::unique_ptr<EVP_CIPHER_CTX, CipherCtxFree> ctx(EVP_CIPHER_CTX_new());
    if (!ctx || EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1)
        throw std::runtime_error("OpenSSL AES-256-GCM initialization failed");
    int n = 0;
    if (!aad.empty() && EVP_DecryptUpdate(ctx.get(), nullptr, &n, aad.data(), static_cast<int>(aad.size())) != 1)
        throw std::runtime_error("OpenSSL AES-GCM AAD failed");
    const std::size_t ct_size = ciphertext_and_tag.size() - 16;
    std::vector<std::uint8_t> out(ct_size ? ct_size : 1);
    int written = 0;
    if (ct_size && EVP_DecryptUpdate(ctx.get(), out.data(), &written, ciphertext_and_tag.data(), static_cast<int>(ct_size)) != 1)
        throw std::runtime_error("OpenSSL AES-GCM decryption failed");
    auto *tag = const_cast<std::uint8_t *>(ciphertext_and_tag.data() + ct_size);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16, tag) != 1)
        throw std::runtime_error("OpenSSL AES-GCM tag setup failed");
    int tail = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), out.data() + written, &tail) != 1)
        throw std::runtime_error("AES-256-GCM authentication failed");
    out.resize(static_cast<std::size_t>(written + tail));
    return out;
}

std::vector<std::uint8_t> argon2id (Bytes credential, Bytes salt, std::uint32_t memory_kib,
                                    std::uint32_t passes, std::uint32_t parallelism)
{
    if (salt.size() < 8 || salt.size() > 1024 || memory_kib < 8 * parallelism ||
        passes == 0 || parallelism == 0)
        throw std::invalid_argument("invalid QTL Argon2id parameters");
    static constexpr char prefix[] = "E46-QTL-2\0password\0";
    std::vector<std::uint8_t> framed(prefix, prefix + sizeof(prefix) - 1);
    framed.insert(framed.end(), credential.begin(), credential.end());

    std::unique_ptr<EVP_KDF, KdfFree> kdf(EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr));
    if (!kdf)
        throw std::runtime_error("OpenSSL ARGON2ID KDF is unavailable");
    std::unique_ptr<EVP_KDF_CTX, KdfCtxFree> ctx(EVP_KDF_CTX_new(kdf.get()));
    if (!ctx)
        throw std::runtime_error("EVP_KDF_CTX_new(ARGON2ID) failed");
    std::uint32_t iter = passes, threads = parallelism, lanes = parallelism;
    std::uint32_t memcost = memory_kib, version = 19;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, framed.data(), framed.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<std::uint8_t *>(salt.data()), salt.size()),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iter),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, &threads),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &lanes),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &memcost),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_VERSION, &version),
        OSSL_PARAM_construct_end()
    };
    std::vector<std::uint8_t> out(32);
    if (EVP_KDF_derive(ctx.get(), out.data(), out.size(), params) != 1)
        throw std::runtime_error("OpenSSL ARGON2ID derive failed");
    OPENSSL_cleanse(framed.data(), framed.size());
    return out;
}
} // namespace e46::qtl_v2
