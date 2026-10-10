#include "e46/addresses.hpp"
#include "e46/keys.hpp"
#include "e46/qtl_v2.hpp"
#include "e46/transaction.hpp"
#include "hex.hpp"
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <algorithm>
#include <array>
#include <charconv>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <fcntl.h>
#include <iterator>
#include <iostream>
#include <limits>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#include <vector>

namespace addr = e46::addresses;
namespace keys = e46::keys;
namespace qtl = e46::qtl_v2;
namespace tx = e46::transaction;
namespace tool = e46::rl::tool;

namespace
{
constexpr std::uint32_t kdf_memory_kib = 65'536;
constexpr std::uint32_t kdf_passes = 1;
constexpr std::uint32_t kdf_lanes = 1;
constexpr std::uint32_t lock_a_steps = 75'000;
constexpr std::uint32_t lock_b_steps = 1'450'000;
constexpr std::uint32_t checkpoint_count = 5;
constexpr std::size_t rsa_bytes = 256;
constexpr std::size_t wallet_seed_bytes = 32;
constexpr std::string_view safety_notice =
    "QTL is an experimental research lock for test data only. Never use it for physical access or anything where a failed or delayed unlock could endanger a person.";
constexpr std::array<std::uint8_t, 8> wallet_magic{'E','4','6','Q','T','L','W','2'};

struct BnFree { void operator()(BIGNUM *p) const noexcept { BN_clear_free(p); } };
struct BnCtxFree { void operator()(BN_CTX *p) const noexcept { BN_CTX_free(p); } };
struct PkeyFree { void operator()(EVP_PKEY *p) const noexcept { EVP_PKEY_free(p); } };
struct PkeyCtxFree { void operator()(EVP_PKEY_CTX *p) const noexcept { EVP_PKEY_CTX_free(p); } };
using Bn = std::unique_ptr<BIGNUM, BnFree>;
struct WipeVector
{
    std::vector<std::uint8_t> &value;
    ~WipeVector () { if (!value.empty()) OPENSSL_cleanse(value.data(), value.size()); }
};
struct WipeString
{
    std::string &value;
    ~WipeString () { if (!value.empty()) OPENSSL_cleanse(value.data(), value.size()); }
};
struct WipeKeyPair
{
    keys::KeyPair &value;
    ~WipeKeyPair () { OPENSSL_cleanse(value.private_key.data(), value.private_key.size()); }
};

struct WalletEnvelope
{
    std::vector<std::uint8_t> salt, nonce, password_check, modulus, base;
    std::vector<std::uint32_t> marks_a, marks_b;
    std::vector<std::vector<std::uint8_t>> commits_a, commits_b;
    std::vector<std::uint8_t> seed_nonce, wrapped_seed, ciphertext;
};

[[noreturn]] void fail (std::string_view message) { throw std::runtime_error(std::string(message)); }

std::vector<std::uint8_t> random_bytes (std::size_t count)
{
    std::vector<std::uint8_t> out(count);
    if (count && RAND_bytes(out.data(), static_cast<int>(count)) != 1)
        fail("OS random generator failed");
    return out;
}

template <std::size_t N> std::array<std::uint8_t, N> random_array ()
{
    std::array<std::uint8_t, N> out{};
    if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1)
        fail("OS random generator failed");
    return out;
}

void put_u16le (std::vector<std::uint8_t> &out, std::uint16_t n)
{
    out.push_back(static_cast<std::uint8_t>(n)); out.push_back(static_cast<std::uint8_t>(n >> 8));
}
void put_u32le (std::vector<std::uint8_t> &out, std::uint32_t n)
{
    for (unsigned i = 0; i < 4; ++i) out.push_back(static_cast<std::uint8_t>(n >> (8 * i)));
}
std::uint16_t get_u16le (std::span<const std::uint8_t> in, std::size_t &p)
{
    if (p + 2 > in.size()) fail("truncated wallet file");
    const auto n = static_cast<std::uint16_t>(in[p] | (static_cast<std::uint16_t>(in[p + 1]) << 8)); p += 2; return n;
}
std::uint8_t get_u8 (std::span<const std::uint8_t> in, std::size_t &p)
{
    if (p >= in.size()) fail("truncated wallet file");
    return in[p++];
}
std::uint32_t get_u32le (std::span<const std::uint8_t> in, std::size_t &p)
{
    if (p + 4 > in.size()) fail("truncated wallet file");
    std::uint32_t n = 0; for (unsigned i = 0; i < 4; ++i) n |= static_cast<std::uint32_t>(in[p++]) << (8 * i); return n;
}
void append (std::vector<std::uint8_t> &out, std::span<const std::uint8_t> v)
{ out.insert(out.end(), v.begin(), v.end()); }
std::vector<std::uint8_t> take (std::span<const std::uint8_t> in, std::size_t &p, std::size_t n)
{
    if (n > in.size() - std::min(p, in.size())) fail("truncated wallet file");
    std::vector<std::uint8_t> out(in.begin() + static_cast<std::ptrdiff_t>(p), in.begin() + static_cast<std::ptrdiff_t>(p + n)); p += n; return out;
}

std::vector<std::uint8_t> header_bytes (const WalletEnvelope &w)
{
    std::vector<std::uint8_t> out(wallet_magic.begin(), wallet_magic.end());
    out.push_back(1); // fixed, allow-listed toy profile
    put_u32le(out, kdf_memory_kib); put_u32le(out, kdf_passes); put_u32le(out, kdf_lanes);
    append(out, w.salt); append(out, w.nonce); append(out, w.password_check);
    append(out, w.modulus); append(out, w.base);
    put_u32le(out, lock_a_steps); out.push_back(static_cast<std::uint8_t>(w.marks_a.size()));
    for (std::size_t i = 0; i < w.marks_a.size(); ++i)
    { put_u32le(out, w.marks_a[i]); append(out, w.commits_a.at(i)); }
    put_u32le(out, lock_b_steps); out.push_back(static_cast<std::uint8_t>(w.marks_b.size()));
    for (std::size_t i = 0; i < w.marks_b.size(); ++i)
    { put_u32le(out, w.marks_b[i]); append(out, w.commits_b.at(i)); }
    append(out, w.seed_nonce); append(out, w.wrapped_seed);
    put_u16le(out, static_cast<std::uint16_t>(safety_notice.size()));
    append(out, std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(safety_notice.data()), safety_notice.size()));
    return out;
}

std::vector<std::uint8_t> serialize_wallet (const WalletEnvelope &w)
{
    const auto header = header_bytes(w);
    std::vector<std::uint8_t> out;
    put_u32le(out, static_cast<std::uint32_t>(header.size())); append(out, header);
    put_u32le(out, static_cast<std::uint32_t>(w.ciphertext.size())); append(out, w.ciphertext);
    return out;
}

WalletEnvelope parse_wallet (std::span<const std::uint8_t> bytes)
{
    std::size_t p = 0;
    const auto header_size = get_u32le(bytes, p);
    if (header_size > bytes.size() - p) fail("truncated wallet header");
    const auto h = bytes.subspan(p, header_size); p += header_size;
    const auto cipher_size = get_u32le(bytes, p);
    if (cipher_size > bytes.size() - p || p + cipher_size != bytes.size()) fail("invalid wallet ciphertext length");
    WalletEnvelope w; std::size_t hp = 0;
    const auto magic = take(h, hp, wallet_magic.size());
    if (!std::equal(magic.begin(), magic.end(), wallet_magic.begin())) fail("unsupported wallet format");
    if (get_u8(h, hp) != 1 || get_u32le(h, hp) != kdf_memory_kib || get_u32le(h, hp) != kdf_passes || get_u32le(h, hp) != kdf_lanes)
        fail("wallet profile is not allow-listed");
    w.salt = take(h, hp, 16); w.nonce = take(h, hp, 12); w.password_check = take(h, hp, 16);
    w.modulus = take(h, hp, rsa_bytes); w.base = take(h, hp, rsa_bytes);
    Bn modulus(BN_bin2bn(w.modulus.data(), static_cast<int>(w.modulus.size()), nullptr));
    Bn base(BN_bin2bn(w.base.data(), static_cast<int>(w.base.size()), nullptr));
    if (!modulus || !base || BN_num_bits(modulus.get()) != 2048 || !BN_is_odd(modulus.get()) ||
        BN_is_zero(base.get()) || BN_is_one(base.get()) || BN_cmp(base.get(), modulus.get()) >= 0)
        fail("invalid RSA puzzle values");
    if (get_u32le(h, hp) != lock_a_steps || get_u8(h, hp) != checkpoint_count) fail("invalid Lock-A profile");
    for (unsigned i = 0; i < checkpoint_count; ++i) { w.marks_a.push_back(get_u32le(h, hp)); w.commits_a.push_back(take(h, hp, 16)); }
    if (get_u32le(h, hp) != lock_b_steps || get_u8(h, hp) != checkpoint_count) fail("invalid Lock-B profile");
    for (unsigned i = 0; i < checkpoint_count; ++i) { w.marks_b.push_back(get_u32le(h, hp)); w.commits_b.push_back(take(h, hp, 16)); }
    w.seed_nonce = take(h, hp, 12); w.wrapped_seed = take(h, hp, 48);
    const auto safety_n = get_u16le(h, hp);
    const auto safety = take(h, hp, safety_n);
    if (std::string_view(reinterpret_cast<const char *>(safety.data()), safety.size()) != safety_notice || hp != h.size())
        fail("invalid wallet safety header");
    w.ciphertext = take(bytes, p, cipher_size);
    if (p != bytes.size() || w.ciphertext.size() != wallet_seed_bytes + 16) fail("invalid wallet envelope length");
    const auto expected_a = [&] { std::vector<std::uint32_t> v; for (unsigned i = 1; i <= checkpoint_count; ++i) v.push_back(lock_a_steps * i / checkpoint_count); return v; }();
    const auto expected_b = [&] { std::vector<std::uint32_t> v; for (unsigned i = 1; i <= checkpoint_count; ++i) v.push_back(lock_b_steps * i / checkpoint_count); return v; }();
    if (w.marks_a != expected_a || w.marks_b != expected_b) fail("wallet checkpoint layout is not allow-listed");
    return w;
}

std::vector<std::uint8_t> read_file (const std::string &path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f) fail("cannot open wallet file");
    std::vector<std::uint8_t> out((std::istreambuf_iterator<char>(f)), {});
    if (out.size() > 1'000'000) fail("wallet file exceeds size limit");
    return out;
}

void write_new_private_file (const std::string &path, std::span<const std::uint8_t> bytes)
{
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
    if (fd < 0) fail(errno == EEXIST ? "wallet file already exists" : "cannot create wallet file");
    std::size_t p = 0;
    while (p < bytes.size())
    {
        const auto n = ::write(fd, bytes.data() + p, bytes.size() - p);
        if (n <= 0) { const int saved = errno; ::close(fd); ::unlink(path.c_str()); errno = saved; fail("wallet write failed"); }
        p += static_cast<std::size_t>(n);
    }
    if (::fsync(fd) != 0) { ::close(fd); fail("wallet fsync failed"); }
    if (::close(fd) != 0) fail("wallet close failed");
}

std::string read_secret (std::string_view prompt)
{
    if (!::isatty(STDIN_FILENO))
    {
        std::cerr << prompt << std::flush;
        std::string value; if (!std::getline(std::cin, value)) fail("password input unavailable"); return value;
    }
    termios old_state{};
    if (tcgetattr(STDIN_FILENO, &old_state) != 0) fail("cannot configure password input");
    termios hidden = old_state; hidden.c_lflag &= static_cast<tcflag_t>(~ECHO);
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) != 0) fail("cannot hide password input");
    // Advertise readiness only after TCSAFLUSH has discarded any queued input.
    // A terminal client may respond immediately when it sees this prompt.
    std::cerr << prompt << std::flush;
    std::string value; std::getline(std::cin, value);
    const int restored = tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_state);
    std::cerr << '\n';
    if (restored != 0 || !std::cin) fail("password input failed");
    return value;
}

std::vector<std::uint8_t> bytes_of (std::string_view s)
{ return {reinterpret_cast<const std::uint8_t *>(s.data()), reinterpret_cast<const std::uint8_t *>(s.data()) + s.size()}; }

std::span<const std::uint8_t> minimal_integer (std::span<const std::uint8_t> v)
{
    while (v.size() > 1 && v.front() == 0) v = v.subspan(1);
    return v;
}

std::vector<std::uint8_t> fast_rsw (std::span<const std::uint8_t> x_bytes,
                                   std::span<const std::uint8_t> n_bytes,
                                   const BIGNUM *phi, std::uint32_t squarings)
{
    Bn x(BN_bin2bn(x_bytes.data(), static_cast<int>(x_bytes.size()), nullptr));
    Bn n(BN_bin2bn(n_bytes.data(), static_cast<int>(n_bytes.size()), nullptr));
    Bn exponent(BN_new()), two(BN_new()), t(BN_new()), y(BN_new());
    std::unique_ptr<BN_CTX, BnCtxFree> ctx(BN_CTX_new());
    if (!x || !n || !exponent || !two || !t || !y || !ctx) fail("RSA puzzle allocation failed");
    BN_set_word(two.get(), 2); BN_set_word(t.get(), squarings);
    if (BN_mod_exp(exponent.get(), two.get(), t.get(), phi, ctx.get()) != 1 ||
        BN_mod_exp(y.get(), x.get(), exponent.get(), n.get(), ctx.get()) != 1) fail("RSA puzzle computation failed");
    std::vector<std::uint8_t> out(n_bytes.size());
    if (BN_bn2binpad(y.get(), out.data(), static_cast<int>(out.size())) != static_cast<int>(out.size())) fail("RSA puzzle encoding failed");
    return out;
}

std::vector<std::uint8_t> make_aad (std::string_view label, std::string_view profile,
                                    std::span<const std::uint8_t> salt = {})
{
    std::vector<std::uint8_t> out{'E','4','6','-','Q','T','L','-','2',0};
    append(out, bytes_of(label)); out.push_back(0); append(out, bytes_of(profile)); append(out, salt); return out;
}

std::vector<std::uint8_t> password_kdf (std::string_view password, std::span<const std::uint8_t> salt)
{
    const long pages = sysconf(_SC_PHYS_PAGES), page_size = sysconf(_SC_PAGESIZE);
    if (pages <= 0 || page_size <= 0) fail("cannot determine available physical memory");
    const auto total = static_cast<std::uint64_t>(pages) * static_cast<std::uint64_t>(page_size);
    if (static_cast<std::uint64_t>(kdf_memory_kib) * 1024 > total / 2) fail("machine has insufficient RAM for the QTL profile");
    return qtl::argon2id(bytes_of(password), salt, kdf_memory_kib, kdf_passes, kdf_lanes);
}

WalletEnvelope seal_seed (std::span<const std::uint8_t> seed, std::string_view password)
{
    if (seed.size() != wallet_seed_bytes || password.empty()) fail("seed and nonempty password are required");
    WalletEnvelope w;
    w.salt = random_bytes(16); w.nonce = random_bytes(12); w.seed_nonce = random_bytes(12);

    std::unique_ptr<EVP_PKEY_CTX, PkeyCtxFree> keyctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
    EVP_PKEY *raw_key = nullptr;
    if (!keyctx || EVP_PKEY_keygen_init(keyctx.get()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(keyctx.get(), 2048) <= 0 || EVP_PKEY_keygen(keyctx.get(), &raw_key) <= 0)
        fail("RSA puzzle key generation failed");
    std::unique_ptr<EVP_PKEY, PkeyFree> rsa(raw_key);
    BIGNUM *n_raw = nullptr, *p_raw = nullptr, *q_raw = nullptr;
    if (EVP_PKEY_get_bn_param(rsa.get(), OSSL_PKEY_PARAM_RSA_N, &n_raw) != 1 ||
        EVP_PKEY_get_bn_param(rsa.get(), OSSL_PKEY_PARAM_RSA_FACTOR1, &p_raw) != 1 ||
        EVP_PKEY_get_bn_param(rsa.get(), OSSL_PKEY_PARAM_RSA_FACTOR2, &q_raw) != 1)
    { BN_clear_free(n_raw); BN_clear_free(p_raw); BN_clear_free(q_raw); fail("RSA trapdoor extraction failed"); }
    Bn n(n_raw), p(p_raw), q(q_raw);
    Bn pm1(BN_dup(p.get())), qm1(BN_dup(q.get())), phi(BN_new()), x(BN_new()), n_minus(BN_dup(n.get()));
    std::unique_ptr<BN_CTX, BnCtxFree> bnctx(BN_CTX_new());
    if (!pm1 || !qm1 || !phi || !x || !n_minus || !bnctx || BN_sub_word(pm1.get(), 1) != 1 ||
        BN_sub_word(qm1.get(), 1) != 1 || BN_mul(phi.get(), pm1.get(), qm1.get(), bnctx.get()) != 1 ||
        BN_sub_word(n_minus.get(), 3) != 1 || BN_rand_range(x.get(), n_minus.get()) != 1 || BN_add_word(x.get(), 2) != 1)
        fail("RSA puzzle parameters failed");
    w.modulus.resize(rsa_bytes); w.base.resize(rsa_bytes);
    if (BN_bn2binpad(n.get(), w.modulus.data(), static_cast<int>(rsa_bytes)) != static_cast<int>(rsa_bytes) ||
        BN_bn2binpad(x.get(), w.base.data(), static_cast<int>(rsa_bytes)) != static_cast<int>(rsa_bytes)) fail("RSA puzzle encoding failed");
    for (unsigned i = 1; i <= checkpoint_count; ++i)
    {
        const auto mark = lock_a_steps * i / checkpoint_count;
        const auto y = fast_rsw(w.base, w.modulus, phi.get(), mark);
        w.marks_a.push_back(mark); w.commits_a.push_back(qtl::checkpoint_commit('A', i, minimal_integer(y)));
    }

    auto chain_seed = random_bytes(32); WipeVector wipe_chain_seed{chain_seed};
    auto state_b = chain_seed; WipeVector wipe_state_b{state_b};
    for (unsigned i = 1; i <= checkpoint_count; ++i)
    {
        const auto mark = lock_b_steps * i / checkpoint_count;
        const auto previous = lock_b_steps * (i - 1) / checkpoint_count;
        state_b = qtl::lock_b_advance(state_b, mark - previous);
        w.marks_b.push_back(mark); w.commits_b.push_back(qtl::checkpoint_commit('B', i, state_b));
    }
    auto y_a = fast_rsw(w.base, w.modulus, phi.get(), lock_a_steps); WipeVector wipe_y_a{y_a};
    const auto &y_b = state_b;
    auto k_pw = password_kdf(password, w.salt); WipeVector wipe_k_pw{k_pw};
    w.password_check = qtl::password_check(k_pw, w.salt);
    auto seed_key = e46::shake::kmac256(k_pw, w.salt, 32, "E46-QTL-2 Lock-B seed"); WipeVector wipe_seed_key{seed_key};
    const auto seed_aad = make_aad("lock-b-seed", "toy", w.salt);
    w.wrapped_seed = qtl::aes256gcm_encrypt(seed_key, w.seed_nonce, chain_seed, seed_aad);
    auto final = qtl::final_key(k_pw, y_a, y_b); WipeVector wipe_final{final};
    const auto aad = header_bytes(w);
    w.ciphertext = qtl::aes256gcm_encrypt(final, w.nonce, seed, aad);
    return w;
}

std::vector<std::uint8_t> unlock_seed (std::span<const std::uint8_t> file,
                                      std::string_view fingerprint_hex,
                                      std::string_view password)
{
    const auto expected = tool::unhex(std::string(fingerprint_hex));
    if (expected.size() != 32) fail("fingerprint must be 32-byte hex");
    const auto actual = qtl::fingerprint(file);
    if (CRYPTO_memcmp(actual.data(), expected.data(), actual.size()) != 0) fail("fingerprint mismatch");
    auto w = parse_wallet(file);
    auto k_pw = password_kdf(password, w.salt); WipeVector wipe_k_pw{k_pw};
    const auto check = qtl::password_check(k_pw, w.salt);
    if (CRYPTO_memcmp(check.data(), w.password_check.data(), check.size()) != 0) fail("wrong password");
    auto seed_key = e46::shake::kmac256(k_pw, w.salt, 32, "E46-QTL-2 Lock-B seed"); WipeVector wipe_seed_key{seed_key};
    const auto seed_aad = make_aad("lock-b-seed", "toy", w.salt);
    auto chain_seed = qtl::aes256gcm_decrypt(seed_key, w.seed_nonce, w.wrapped_seed, seed_aad); WipeVector wipe_chain_seed{chain_seed};

    auto state_a = w.base; WipeVector wipe_state_a{state_a};
    std::uint32_t done_a = 0;
    for (std::size_t i = 0; i < w.marks_a.size(); ++i)
    {
        const auto count = w.marks_a[i] - done_a;
        state_a = qtl::lock_a_advance(state_a, w.modulus, count); done_a = w.marks_a[i];
        const auto minimal = minimal_integer(state_a);
        const auto expected = qtl::checkpoint_commit('A', static_cast<std::uint32_t>(i + 1), minimal);
        if (CRYPTO_memcmp(expected.data(), w.commits_a[i].data(), expected.size()) != 0) fail("Lock-A checkpoint failed");
    }
    auto state_b = chain_seed; WipeVector wipe_state_b{state_b};
    std::uint32_t done_b = 0;
    for (std::size_t i = 0; i < w.marks_b.size(); ++i)
    {
        state_b = qtl::lock_b_advance(state_b, w.marks_b[i] - done_b); done_b = w.marks_b[i];
        const auto commit = qtl::checkpoint_commit('B', static_cast<std::uint32_t>(i + 1), state_b);
        if (CRYPTO_memcmp(commit.data(), w.commits_b[i].data(), commit.size()) != 0) fail("Lock-B checkpoint failed");
    }
    auto final = qtl::final_key(k_pw, state_a, state_b); WipeVector wipe_final{final};
    const auto aad = header_bytes(w);
    return qtl::aes256gcm_decrypt(final, w.nonce, w.ciphertext, aad);
}

std::uint64_t number (std::string_view s)
{
    std::uint64_t n{}; const auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), n);
    if (ec != std::errc{} || end != s.data() + s.size()) fail("invalid unsigned integer"); return n;
}
std::uint32_t number32 (std::string_view s)
{
    const auto n = number(s); if (n > std::numeric_limits<std::uint32_t>::max()) fail("integer exceeds 32-bit range");
    return static_cast<std::uint32_t>(n);
}

struct SpentDescription
{
    tx::Input input;
    tx::SpentCoin coin;
    std::uint32_t key_index{};
};

SpentDescription parse_spent (std::string_view s)
{
    std::array<std::string, 7> f{}; std::size_t pos = 0;
    for (std::size_t i = 0; i < f.size(); ++i)
    {
        const auto sep = s.find(':', pos); if (i + 1 < f.size() && sep == std::string_view::npos) fail("spent descriptor has 7 colon-separated fields");
        const auto end = (i + 1 == f.size()) ? s.size() : sep; f[i] = s.substr(pos, end - pos); pos = end + 1;
    }
    if (f[0].size() != 64) fail("spent txid must be 32-byte hex");
    auto prev = tool::unhex(f[0]); SpentDescription d;
    std::copy(prev.begin(), prev.end(), d.input.previous_txid.begin());
    d.input.previous_index = number32(f[1]); d.input.sequence = 0xffffffffU;
    const auto type = number(f[3]); if (type > 255) fail("spent output type outside byte range");
    d.coin.output = {number(f[2]), static_cast<std::uint8_t>(type), f[4] == "-" ? std::vector<std::uint8_t>{} : tool::unhex(f[4])};
    d.coin.is_coinbase = number(f[5]) != 0; d.coin.creation_height = number(f[6]);
    tx::validate_output(d.coin.output);
    return d;
}

std::vector<std::uint8_t> execute_build (int argc, char **argv)
{
    // build WALLET FP SPENT_DESC KEY_INDEX RECIPIENT AMOUNT FEE HEIGHT
    if (argc != 10) fail("build usage: build WALLET FP SPENT_DESC KEY_INDEX RECIPIENT AMOUNT FEE HEIGHT");
    const std::string wallet_path = argv[2], fp = argv[3];
    auto spent_d = parse_spent(argv[4]); spent_d.key_index = number32(argv[5]);
    const std::string recipient = argv[6]; const auto amount = number(argv[7]), fee = number(argv[8]);
    auto password = read_secret("Wallet password: "); WipeString wipe_password{password};
    const auto file = read_file(wallet_path); auto seed = unlock_seed(file, fp, password);
    if (spent_d.coin.output.type != 0) fail("build currently spends single-owner type-0 coins only");
    auto keypair = keys::derive_keypair(seed, 0, spent_d.key_index); WipeKeyPair wipe_keypair{keypair};
    const auto owner_payload = addr::single_owner_payload(keypair.public_key);
    if (!std::equal(owner_payload.begin(), owner_payload.end(), spent_d.coin.output.payload.begin(), spent_d.coin.output.payload.end()))
        fail("spent coin does not belong to this wallet index");
    const auto recipient_payload = addr::decode_single_owner_address(recipient, addr::Network::testnet);
    if (amount == 0 || fee > spent_d.coin.output.value || amount > spent_d.coin.output.value - fee) fail("payment plus fee exceeds spent coin");
    tx::Transaction transaction; transaction.version = 1; transaction.inputs.push_back(spent_d.input);
    transaction.outputs.push_back({amount, 0, {recipient_payload.begin(), recipient_payload.end()}});
    const auto change = spent_d.coin.output.value - amount - fee;
    if (change) transaction.outputs.push_back({change, 0, {spent_d.coin.output.payload.begin(), spent_d.coin.output.payload.end()}});
    transaction.witnesses.emplace_back(tx::SingleOwnerWitness{keypair.public_key, {}});
    std::array<tx::SpentCoin, 1> spent{spent_d.coin};
    const auto message = tx::sighash(transaction, 0, spent);
    const auto signature = keys::sign(keypair.private_key, message);
    transaction.witnesses[0] = tx::SingleOwnerWitness{keypair.public_key, {signature.begin(), signature.end()}};
    tx::validate_transaction(transaction, spent, number(argv[9]));
    OPENSSL_cleanse(seed.data(), seed.size()); OPENSSL_cleanse(password.data(), password.size());
    return tx::serialize(transaction);
}

void print_show (std::span<const std::uint8_t> raw, std::span<const tx::SpentCoin> spent)
{
    const auto t = tx::deserialize(raw, spent);
    std::cout << "version: " << t.version << "\ninputs: " << t.inputs.size() << "\n";
    for (std::size_t i = 0; i < t.inputs.size(); ++i)
    {
        const auto &v = t.inputs[i]; std::cout << "  [" << i << "] txid=" << tool::hex(v.previous_txid)
            << " index=" << v.previous_index << " sequence=" << v.sequence << '\n';
    }
    std::cout << "outputs: " << t.outputs.size() << "\n";
    for (std::size_t i = 0; i < t.outputs.size(); ++i)
    {
        const auto &v = t.outputs[i]; std::cout << "  [" << i << "] value=" << v.value << " type=0x"
            << std::hex << static_cast<unsigned>(v.type) << std::dec << " payload=" << tool::hex(v.payload) << '\n';
    }
    std::cout << "lock_time: " << t.lock_time << "\nwitnesses: " << t.witnesses.size() << '\n';
    for (std::size_t i = 0; i < t.witnesses.size(); ++i)
    {
        std::visit([&] (const auto &w) {
            using W = std::decay_t<decltype(w)>;
            std::cout << "  [" << i << "] ";
            if constexpr (std::is_same_v<W, tx::CoinbaseWitness>)
                std::cout << "coinbase data=" << tool::hex(w.coinbase_data) << '\n';
            else if constexpr (std::is_same_v<W, tx::SingleOwnerWitness>)
                std::cout << "single-owner public_key=" << tool::hex(w.public_key)
                          << " signature_bytes=" << w.signature.size() << '\n';
            else if constexpr (std::is_same_v<W, tx::SharedWitness>)
            {
                std::cout << "shared threshold=" << static_cast<unsigned>(w.threshold)
                          << " keys=" << w.public_keys.size() << " signature_lengths=";
                for (std::size_t j = 0; j < w.signatures.size(); ++j)
                    std::cout << (j ? "," : "") << w.signatures[j].size();
                std::cout << '\n';
            }
            else
                std::cout << "Block-QTL public_key=" << tool::hex(w.public_key)
                          << " signature_bytes=" << w.signature.size() << " salt=" << tool::hex(w.salt) << '\n';
        }, t.witnesses[i]);
    }
    std::cout << "txid: " << tool::hex(tx::txid(t)) << "\nwtxid: " << tool::hex(tx::wtxid(t)) << '\n';
    if (!spent.empty())
        for (std::size_t i = 0; i < t.inputs.size(); ++i) std::cout << "sighash[" << i << "]: " << tool::hex(tx::sighash(t, static_cast<std::uint32_t>(i), spent)) << '\n';
    std::cout << "serialized: " << tool::hex(tx::serialize(t)) << '\n';
}

void usage ()
{
    std::cerr << "e46-wallet (offline; testnet only)\n"
      << "  new WALLET [--show-secret]\n  address INDEX --wallet WALLET --fingerprint HEX\n"
      << "  build WALLET FP SPENT_DESC KEY_INDEX RECIPIENT AMOUNT FEE HEIGHT\n"
      << "  show TX_HEX [SPENT_DESC]\n  unlock WALLET FP [--show-secret]\n"
      << "  lock WALLET FP NEW_WALLET\n";
}
} // namespace

int main (int argc, char **argv)
{
    try
    {
        if (argc < 2) { usage(); return 2; }
        const std::string command = argv[1];
        if (command == "new")
        {
            if (argc < 3 || argc > 4 || (argc == 4 && std::string(argv[3]) != "--show-secret")) fail("new usage: new WALLET [--show-secret]");
            const std::string path = argv[2]; auto password = read_secret("New wallet password: "); WipeString wipe_password{password};
            if (password.size() < 12) fail("password must be at least 12 bytes");
            auto confirm = read_secret("Confirm password: "); WipeString wipe_confirm{confirm}; if (confirm != password) fail("passwords do not match");
            auto seed = random_bytes(wallet_seed_bytes); WipeVector wipe_seed{seed}; auto w = seal_seed(seed, password); auto file = serialize_wallet(w);
            const auto fp = qtl::fingerprint(file); write_new_private_file(path, file);
            std::cout << "Wallet created: " << path << "\nSafety: QTL is for test data only; never use it for physical access.\n"
                      << "Fingerprint (keep outside the wallet file): " << tool::hex(fp)
                      << "\nMake 2–3 backup copies and verify this fingerprint for each copy.\n";
            if (argc == 4) std::cout << "MASTER SEED (--show-secret): " << tool::hex(seed) << '\n';
            return 0;
        }
        if (command == "unlock")
        {
            if (argc < 4 || argc > 5 || (argc == 5 && std::string(argv[4]) != "--show-secret")) fail("unlock usage: unlock WALLET FP [--show-secret]");
            auto password = read_secret("Wallet password: "); WipeString wipe_password{password}; const auto file = read_file(argv[2]); auto seed = unlock_seed(file, argv[3], password); WipeVector wipe_seed{seed};
            std::cout << "Wallet unlocked and fingerprint verified.\n";
            if (argc == 5) std::cout << "MASTER SEED (--show-secret): " << tool::hex(seed) << '\n';
            return 0;
        }
        if (command == "address")
        {
            if (argc != 7 || std::string(argv[3]) != "--wallet" || std::string(argv[5]) != "--fingerprint")
                fail("address usage: address INDEX --wallet WALLET --fingerprint HEX");
            const auto index = number32(argv[2]);
            auto password = read_secret("Wallet password: "); WipeString wipe_password{password}; const auto file = read_file(argv[4]); auto seed = unlock_seed(file, argv[6], password); WipeVector wipe_seed{seed};
            auto pair = keys::derive_keypair(seed, 0, index); WipeKeyPair wipe_pair{pair};
            std::cout << addr::single_owner_address(pair.public_key, addr::Network::testnet) << '\n';
            return 0;
        }
        if (command == "build")
        {
            const auto raw = execute_build(argc, argv); std::cout << tool::hex(raw) << '\n'; return 0;
        }
        if (command == "show")
        {
            if (argc < 3 || argc > 4) fail("show usage: show TX_HEX [SPENT_DESC]");
            const auto raw = tool::unhex(argv[2]); std::vector<tx::SpentCoin> spent;
            if (argc == 4) spent.push_back(parse_spent(argv[3]).coin);
            print_show(raw, spent); return 0;
        }
        if (command == "lock")
        {
            if (argc != 5) fail("lock usage: lock WALLET FP NEW_WALLET");
            auto old_password = read_secret("Current wallet password: "); WipeString wipe_old_password{old_password}; const auto file = read_file(argv[2]); auto seed = unlock_seed(file, argv[3], old_password); WipeVector wipe_seed{seed};
            auto password = read_secret("New wallet password: "); WipeString wipe_password{password}; if (password.size() < 12) fail("password must be at least 12 bytes");
            auto confirm = read_secret("Confirm new password: "); WipeString wipe_confirm{confirm}; if (confirm != password) fail("passwords do not match");
            const auto w = seal_seed(seed, password); const auto output = serialize_wallet(w); const auto fp = qtl::fingerprint(output);
            write_new_private_file(argv[4], output); std::cout << "Wallet re-locked: " << argv[4] << "\nFingerprint: " << tool::hex(fp) << '\n';
            return 0;
        }
        usage(); return 2;
    }
    catch (const std::exception &e) { std::cerr << "e46-wallet: " << e.what() << '\n'; return 1; }
}
