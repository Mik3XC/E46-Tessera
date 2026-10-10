#pragma once

#include <cstdint>
#include <vector>

namespace e46::emission
{
inline constexpr std::uint64_t epoch_blocks = 17'280;
inline constexpr std::uint64_t epochs_per_table_year = 12;
inline constexpr std::uint64_t coinbase_maturity = 100;
inline constexpr std::uint64_t base_units_per_coin = 100'000'000;
inline constexpr std::uint64_t total_supply = 46'000'000 * base_units_per_coin;
inline constexpr std::uint64_t neutrino = 1;
inline constexpr unsigned decay_shift = 20;
inline constexpr std::uint64_t n_stake_multiplier = 576;

struct Shares
{
    std::uint64_t miner{};
    std::uint64_t n_pool{};
    std::uint64_t z_pool{};
    bool operator== (const Shares &) const = default;
};

struct PoolBalances
{
    std::uint64_t n_pool{};
    std::uint64_t z_pool{};
    bool operator== (const PoolBalances &) const = default;
};

struct E46iSpend
{
    std::uint64_t spendable{};
    std::uint64_t burnt{};
    bool operator== (const E46iSpend &) const = default;
};

std::uint64_t reward_at (std::uint64_t height);
std::vector<std::uint64_t> reward_epochs (std::uint64_t count);
Shares split_reward (std::uint64_t reward) noexcept;
std::uint64_t n_stake_cap (std::uint64_t origin_subsidy);
std::uint64_t z_finder_cap (std::uint64_t collision_subsidy) noexcept;

PoolBalances accrue_pools (PoolBalances balances, std::uint64_t reward);
std::uint64_t claim_n_pool (PoolBalances &balances, std::uint64_t requested) noexcept;
std::uint64_t claim_z_pool (PoolBalances &balances, std::uint64_t requested,
                            std::uint64_t collision_subsidy) noexcept;

// E46i payouts are coinbase outputs: they mature after 100 blocks, then remain
// spendable at their epoch-adjusted value. There is no 100-block expiry.
E46iSpend spend_e46i (std::uint64_t amount, std::uint64_t paid_height,
                      std::uint64_t spend_height);
} // namespace e46::emission
