#include "e46/shake.hpp"
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <stdexcept>
#include <string>

namespace e46::shake
{
namespace
{
struct MdCtxFree
{
    void operator()(EVP_MD_CTX *p) const noexcept
    {
        EVP_MD_CTX_free(p);
    }
};
struct MacFree
{
    void operator()(EVP_MAC *p) const noexcept
    {
        EVP_MAC_free(p);
    }
};
struct MacCtxFree
{
    void operator()(EVP_MAC_CTX *p) const noexcept
    {
        EVP_MAC_CTX_free(p);
    }
};
using MdCtx = std::unique_ptr<EVP_MD_CTX, MdCtxFree>;

[[noreturn]] void fail (const char *what)
{
    throw std::runtime_error(std::string("OpenSSL failure: ") + what);
}

const EVP_MD *shake_md ()
{
    // Fetched once; OpenSSL keeps it for the process lifetime.
    static EVP_MD *md = EVP_MD_fetch(nullptr, "SHAKE256", nullptr);
    if (!md)
        fail("EVP_MD_fetch(SHAKE256)");
    return md;
}

void check_tag (std::string_view tag)
{
    if (tag.empty())
        throw std::invalid_argument("Empty domain tag");
    for (char c : tag)
        if (c < 0x21 || c > 0x7E)
            throw std::invalid_argument("Domain tag must be printable ASCII without spaces or NUL");
}

void check_out_len (std::size_t out_len)
{
    if (out_len > max_output_bytes)
        throw std::invalid_argument("SHAKE256 output length exceeds wrapper policy");
}
} // namespace

struct Shake256::Impl
{
    MdCtx ctx{EVP_MD_CTX_new()};
    bool finalized = false;
};

Shake256::Shake256 () : impl_(std::make_unique<Impl>())
{
    if (!impl_->ctx || EVP_DigestInit_ex2(impl_->ctx.get(), shake_md(), nullptr) != 1)
        fail("EVP_DigestInit_ex2(SHAKE256)");
}

Shake256 Shake256::tagged (std::string_view tag)
{
    check_tag(tag);
    Shake256 h;
    const auto *p = reinterpret_cast<const std::uint8_t *>(tag.data());
    h.update(Bytes(p, tag.size()));
    const std::uint8_t zero = 0;
    h.update(Bytes(&zero, 1));
    return h;
}

Shake256::Shake256 (Shake256 &&) noexcept = default;
Shake256 &Shake256::operator=(Shake256 &&) noexcept = default;
Shake256::~Shake256 () = default;

void Shake256::update (Bytes data)
{
    if (!impl_)
        throw std::logic_error("SHAKE256 object was moved from");
    if (impl_->finalized)
        throw std::logic_error("SHAKE256 update after finalize");
    if (!data.empty() && EVP_DigestUpdate(impl_->ctx.get(), data.data(), data.size()) != 1)
        fail("EVP_DigestUpdate");
}

std::vector<std::uint8_t> Shake256::finalize (std::size_t out_len)
{
    if (!impl_)
        throw std::logic_error("SHAKE256 object was moved from");
    if (impl_->finalized)
        throw std::logic_error("SHAKE256 finalize called twice");
    check_out_len(out_len);
    impl_->finalized = true;
    std::vector<std::uint8_t> out(out_len);
    if (out_len && EVP_DigestFinalXOF(impl_->ctx.get(), out.data(), out_len) != 1)
        fail("EVP_DigestFinalXOF");
    return out;
}

std::vector<std::uint8_t> shake256 (Bytes data, std::size_t out_len)
{
    Shake256 h;
    h.update(data);
    return h.finalize(out_len);
}

Digest256 shake256_256 (Bytes data)
{
    const auto v = shake256(data, 32);
    Digest256 d{};
    std::copy(v.begin(), v.end(), d.begin());
    return d;
}

std::vector<std::uint8_t> shake256_tagged (std::string_view tag, Bytes data, std::size_t out_len)
{
    auto h = Shake256::tagged(tag);
    h.update(data);
    return h.finalize(out_len);
}

Digest256 shake256_tagged_256 (std::string_view tag, Bytes data)
{
    const auto v = shake256_tagged(tag, data, 32);
    Digest256 d{};
    std::copy(v.begin(), v.end(), d.begin());
    return d;
}

std::vector<std::uint8_t> kmac256 (Bytes key, Bytes data, std::size_t out_len,
                                   std::string_view customization)
{
    if (key.size() < kmac_min_key_bytes || key.size() > kmac_max_key_bytes)
        throw std::invalid_argument("KMAC256 key length outside 4..512 bytes");
    if (customization.size() > kmac_max_custom_bytes)
        throw std::invalid_argument("KMAC256 customization longer than 512 bytes");
    if (out_len == 0 || out_len > kmac_max_output_bytes)
        throw std::invalid_argument("KMAC256 output length outside 1..2097151 bytes");

    std::unique_ptr<EVP_MAC, MacFree> mac(EVP_MAC_fetch(nullptr, "KMAC256", nullptr));
    if (!mac)
        fail("EVP_MAC_fetch(KMAC256)");
    std::unique_ptr<EVP_MAC_CTX, MacCtxFree> ctx(EVP_MAC_CTX_new(mac.get()));
    if (!ctx)
        fail("EVP_MAC_CTX_new");

    int xof = 0;
    std::size_t size = out_len;
    OSSL_PARAM params[4];
    std::size_t n = 0;
    params[n++] = OSSL_PARAM_construct_int(OSSL_MAC_PARAM_XOF, &xof);
    params[n++] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &size);
    if (!customization.empty())
        params[n++] = OSSL_PARAM_construct_octet_string(
            OSSL_MAC_PARAM_CUSTOM, const_cast<char *>(customization.data()), customization.size());
    params[n] = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(ctx.get(), key.data(), key.size(), params) != 1)
        fail("EVP_MAC_init(KMAC256)");
    if (!data.empty() && EVP_MAC_update(ctx.get(), data.data(), data.size()) != 1)
        fail("EVP_MAC_update");
    std::vector<std::uint8_t> out(out_len);
    std::size_t written = 0;
    if (EVP_MAC_final(ctx.get(), out.data(), &written, out.size()) != 1 || written != out_len)
        fail("EVP_MAC_final");
    return out;
}
} // namespace e46::shake
