#include "e46/keys.hpp"
#include "e46/shake.hpp"
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <algorithm>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>

namespace e46::keys
{
namespace
{
inline constexpr char algorithm[] = "SLH-DSA-SHAKE-128s";
inline constexpr char kat_seed_hex[] =
    "c151951f3811029239b74add24c506afdd30363e156e6fe936ec6ed0231feb5c"
    "529ffe86200d1f32c2b60d0cd909f190";
inline constexpr char kat_private_hex[] =
    "c151951f3811029239b74add24c506afdd30363e156e6fe936ec6ed0231feb5c"
    "529ffe86200d1f32c2b60d0cd909f1900761f9b727afa724b47223016bb5b2ba";
inline constexpr char kat_public_hex[] =
    "529ffe86200d1f32c2b60d0cd909f1900761f9b727afa724b47223016bb5b2ba";

template <std::size_t N>
std::array<std::uint8_t, N> decode_hex (const char (&hex)[2 * N + 1])
{
    auto nibble = [] (char c) -> std::uint8_t {
        if (c >= '0' && c <= '9') return static_cast<std::uint8_t>(c - '0');
        return static_cast<std::uint8_t>(c - 'a' + 10);
    };
    std::array<std::uint8_t, N> result{};
    for (std::size_t i = 0; i < N; ++i)
        result[i] = static_cast<std::uint8_t>((nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]));
    return result;
}

struct PkeyCtxFree
{
    void operator() (EVP_PKEY_CTX *p) const noexcept { EVP_PKEY_CTX_free(p); }
};
struct PkeyFree
{
    void operator() (EVP_PKEY *p) const noexcept { EVP_PKEY_free(p); }
};
struct MdCtxFree
{
    void operator() (EVP_MD_CTX *p) const noexcept { EVP_MD_CTX_free(p); }
};
using PkeyCtx = std::unique_ptr<EVP_PKEY_CTX, PkeyCtxFree>;
using Pkey = std::unique_ptr<EVP_PKEY, PkeyFree>;
using MdCtx = std::unique_ptr<EVP_MD_CTX, MdCtxFree>;

[[noreturn]] void fail (const char *operation)
{
    const auto code = ERR_get_error();
    if (code == 0)
        throw std::runtime_error(std::string("OpenSSL failure: ") + operation);
    char detail[256]{};
    ERR_error_string_n(code, detail, sizeof(detail));
    throw std::runtime_error(std::string("OpenSSL failure: ") + operation + ": " + detail);
}

Pkey import_private (const PrivateKey &private_key)
{
    PkeyCtx context(EVP_PKEY_CTX_new_from_name(nullptr, algorithm, nullptr));
    if (!context)
        fail("EVP_PKEY_CTX_new_from_name(SLH-DSA-SHAKE-128s)");
    if (EVP_PKEY_fromdata_init(context.get()) <= 0)
        fail("EVP_PKEY_fromdata_init");

    auto *private_data = const_cast<std::uint8_t *>(private_key.data());
    auto *public_data = const_cast<std::uint8_t *>(private_key.data() + 32);
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, private_data,
                                          private_key.size()),
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, public_data,
                                          public_key_bytes),
        OSSL_PARAM_construct_end()};
    EVP_PKEY *raw = nullptr;
    if (EVP_PKEY_fromdata(context.get(), &raw, EVP_PKEY_KEYPAIR, parameters) <= 0)
        fail("EVP_PKEY_fromdata(SLH-DSA-SHAKE-128s private key)");
    return Pkey(raw);
}

Pkey import_public (const PublicKey &public_key)
{
    PkeyCtx context(EVP_PKEY_CTX_new_from_name(nullptr, algorithm, nullptr));
    if (!context)
        fail("EVP_PKEY_CTX_new_from_name(SLH-DSA-SHAKE-128s)");
    if (EVP_PKEY_fromdata_init(context.get()) <= 0)
        fail("EVP_PKEY_fromdata_init");
    auto *public_data = const_cast<std::uint8_t *>(public_key.data());
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, public_data,
                                          public_key.size()),
        OSSL_PARAM_construct_end()};
    EVP_PKEY *raw = nullptr;
    if (EVP_PKEY_fromdata(context.get(), &raw, EVP_PKEY_PUBLIC_KEY, parameters) <= 0)
        fail("EVP_PKEY_fromdata(SLH-DSA-SHAKE-128s public key)");
    return Pkey(raw);
}

KeyPair keypair_from_seed_unchecked (const SlhSeed &seed)
{
    PkeyCtx context(EVP_PKEY_CTX_new_from_name(nullptr, algorithm, nullptr));
    if (!context)
        fail("EVP_PKEY_CTX_new_from_name(SLH-DSA-SHAKE-128s)");
    if (EVP_PKEY_keygen_init(context.get()) <= 0)
        fail("EVP_PKEY_keygen_init");
    auto *seed_data = const_cast<std::uint8_t *>(seed.data());
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_SLH_DSA_SEED, seed_data,
                                          seed.size()),
        OSSL_PARAM_construct_end()};
    if (EVP_PKEY_CTX_set_params(context.get(), parameters) <= 0)
        fail("EVP_PKEY_CTX_set_params(SLH-DSA seed)");

    EVP_PKEY *raw = nullptr;
    if (EVP_PKEY_generate(context.get(), &raw) <= 0)
        fail("EVP_PKEY_generate(SLH-DSA-SHAKE-128s)");
    Pkey key(raw);
    KeyPair result{};
    std::size_t private_length = 0, public_length = 0;
    if (EVP_PKEY_get_octet_string_param(key.get(), OSSL_PKEY_PARAM_PRIV_KEY,
                                        result.private_key.data(), result.private_key.size(),
                                        &private_length) <= 0 ||
        EVP_PKEY_get_octet_string_param(key.get(), OSSL_PKEY_PARAM_PUB_KEY,
                                        result.public_key.data(), result.public_key.size(),
                                        &public_length) <= 0)
        fail("EVP_PKEY_get_octet_string_param(SLH-DSA key)");
    if (private_length != result.private_key.size() || public_length != result.public_key.size())
        throw std::runtime_error("Unexpected SLH-DSA-SHAKE-128s key size");
    return result;
}

void check_seeded_keygen_kat (const PrivateKey &expected_private,
                              const PublicKey &expected_public)
{
    const auto seed = decode_hex<slh_seed_bytes>(kat_seed_hex);
    const auto actual = keypair_from_seed_unchecked(seed);
    if (actual.private_key != expected_private || actual.public_key != expected_public)
        throw std::runtime_error("SLH-DSA-SHAKE-128s seeded-keygen KAT failed; refusing key generation");
}

void run_startup_self_test_once ()
{
    static std::once_flag once;
    std::call_once(once, [] {
        check_seeded_keygen_kat(decode_hex<private_key_bytes>(kat_private_hex),
                                decode_hex<public_key_bytes>(kat_public_hex));
    });
}

Signature sign_impl (const PrivateKey &private_key, Bytes message, Bytes context,
                     bool deterministic)
{
    if (context.size() > 255)
        throw std::invalid_argument("SLH-DSA context exceeds 255 bytes");
    auto key = import_private(private_key);
    MdCtx message_context(EVP_MD_CTX_new());
    if (!message_context)
        fail("EVP_MD_CTX_new");
    EVP_PKEY_CTX *key_context = nullptr;
    if (EVP_DigestSignInit_ex(message_context.get(), &key_context, nullptr, nullptr, nullptr,
                              key.get(), nullptr) <= 0)
        fail("EVP_DigestSignInit_ex(SLH-DSA-SHAKE-128s)");

    int deterministic_value = deterministic ? 1 : 0;
    std::uint8_t empty_context_placeholder = 0;
    auto *context_data = context.empty() ? &empty_context_placeholder
                                         : const_cast<std::uint8_t *>(context.data());
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &deterministic_value),
        OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, context_data,
                                          context.size()),
        OSSL_PARAM_construct_end()};
    if (EVP_PKEY_CTX_set_params(key_context, parameters) <= 0)
        fail("EVP_PKEY_CTX_set_params(SLH-DSA signing)");

    Signature signature{};
    std::size_t signature_length = signature.size();
    auto *message_data = const_cast<std::uint8_t *>(message.data());
    if (EVP_DigestSign(message_context.get(), signature.data(), &signature_length,
                       message_data, message.size()) <= 0)
        fail("EVP_DigestSign(SLH-DSA-SHAKE-128s)");
    if (signature_length != signature.size())
        throw std::runtime_error("Unexpected SLH-DSA-SHAKE-128s signature length");
    return signature;
}

} // namespace

SlhSeed derive_seed (Bytes master_seed, std::uint32_t account, std::uint32_t index)
{
    if (master_seed.size() != master_seed_bytes)
        throw std::invalid_argument("E46 master seed must be exactly 32 bytes");
    std::array<std::uint8_t, 15> message{};
    constexpr std::array<std::uint8_t, 7> domain{'E', '4', '6', '-', 'k', 'e', 'y'};
    std::copy(domain.begin(), domain.end(), message.begin());
    for (std::size_t byte = 0; byte < 4; ++byte)
    {
        message[7 + byte] = static_cast<std::uint8_t>(account >> (byte * 8));
        message[11 + byte] = static_cast<std::uint8_t>(index >> (byte * 8));
    }
    const auto result = shake::kmac256(master_seed, message, slh_seed_bytes);
    SlhSeed seed{};
    std::copy(result.begin(), result.end(), seed.begin());
    return seed;
}

KeyPair keypair_from_seed (const SlhSeed &seed)
{
    startup_self_test();
    return keypair_from_seed_unchecked(seed);
}

void startup_self_test ()
{
    run_startup_self_test_once();
}

#ifdef E46_KEYS_TESTING
KeyPair keypair_from_seed_with_expected_kat_for_test (const SlhSeed &seed,
                                                       const PrivateKey &expected_private,
                                                       const PublicKey &expected_public)
{
    check_seeded_keygen_kat(expected_private, expected_public);
    return keypair_from_seed_unchecked(seed);
}
#endif

KeyPair derive_keypair (Bytes master_seed, std::uint32_t account, std::uint32_t index)
{
    return keypair_from_seed(derive_seed(master_seed, account, index));
}

Signature sign (const PrivateKey &private_key, Bytes message, Bytes context)
{
    return sign_impl(private_key, message, context, false);
}

Signature sign_deterministic_for_test (const PrivateKey &private_key, Bytes message,
                                       Bytes context)
{
    return sign_impl(private_key, message, context, true);
}

bool verify (const PublicKey &public_key, Bytes message, Bytes signature, Bytes context)
{
    if (context.size() > 255)
        throw std::invalid_argument("SLH-DSA context exceeds 255 bytes");
    if (signature.size() != signature_bytes)
        return false;
    auto key = import_public(public_key);
    MdCtx message_context(EVP_MD_CTX_new());
    if (!message_context)
        fail("EVP_MD_CTX_new");
    EVP_PKEY_CTX *key_context = nullptr;
    if (EVP_DigestVerifyInit_ex(message_context.get(), &key_context, nullptr, nullptr, nullptr,
                                key.get(), nullptr) <= 0)
        fail("EVP_DigestVerifyInit_ex(SLH-DSA-SHAKE-128s)");
    std::uint8_t empty_context_placeholder = 0;
    auto *context_data = context.empty() ? &empty_context_placeholder
                                         : const_cast<std::uint8_t *>(context.data());
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, context_data,
                                          context.size()),
        OSSL_PARAM_construct_end()};
    if (EVP_PKEY_CTX_set_params(key_context, parameters) <= 0)
        fail("EVP_PKEY_CTX_set_params(SLH-DSA verification)");
    auto *message_data = const_cast<std::uint8_t *>(message.data());
    return EVP_DigestVerify(message_context.get(), signature.data(), signature.size(),
                            message_data, message.size()) == 1;
}
} // namespace e46::keys
