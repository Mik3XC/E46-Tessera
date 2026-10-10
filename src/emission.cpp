#include "e46/emission.hpp"
#include <algorithm>
#include <limits>
#include <stdexcept>

namespace e46::emission
{
namespace
{
std::uint64_t reward_for_epoch (std::uint64_t epoch, std::uint64_t &emitted)
{
    for (std::uint64_t current = 0; current <= epoch; ++current)
    {
        const auto remaining = emitted >= total_supply ? 0 : total_supply - emitted;
        const auto reward = std::max(remaining >> decay_shift, neutrino);
        if (current == epoch || reward == neutrino)
            return reward;
        const auto epoch_emission = epoch_blocks * reward; // bounded by initial supply and safe in u64
        emitted = std::min(total_supply, emitted + epoch_emission);
    }
    throw std::logic_error("unreachable emission epoch state");
}

void add_checked (std::uint64_t &balance, std::uint64_t amount)
{
    if (amount > std::numeric_limits<std::uint64_t>::max() - balance)
        throw std::overflow_error("pool balance overflow");
    balance += amount;
}
} // namespace

std::uint64_t reward_at (std::uint64_t height)
{
    std::uint64_t emitted = 0;
    return reward_for_epoch(height / epoch_blocks, emitted);
}

std::vector<std::uint64_t> reward_epochs (std::uint64_t count)
{
    if (count > static_cast<std::uint64_t>(std::vector<std::uint64_t>{}.max_size()))
        throw std::length_error("reward epoch table too large");
    std::vector<std::uint64_t> rewards;
    rewards.reserve(static_cast<std::size_t>(count));
    std::uint64_t emitted = 0;
    for (std::uint64_t epoch = 0; epoch < count; ++epoch)
    {
        const auto remaining = emitted >= total_supply ? 0 : total_supply - emitted;
        const auto reward = std::max(remaining >> decay_shift, neutrino);
        rewards.push_back(reward);
        if (reward == neutrino)
        {
            rewards.resize(static_cast<std::size_t>(count), neutrino);
            break;
        }
        const auto epoch_emission = epoch_blocks * reward;
        emitted = std::min(total_supply, emitted + epoch_emission);
    }
    return rewards;
}

Shares split_reward (std::uint64_t reward) noexcept
{
    const auto n = reward / 10;
    const auto z = reward / 10;
    return {reward - n - z, n, z};
}

std::uint64_t n_stake_cap (std::uint64_t origin_subsidy)
{
    if (origin_subsidy > std::numeric_limits<std::uint64_t>::max() / n_stake_multiplier)
        throw std::overflow_error("N-pool stake cap overflow");
    return origin_subsidy * n_stake_multiplier;
}

std::uint64_t z_finder_cap (std::uint64_t collision_subsidy) noexcept
{
    return collision_subsidy / 10;
}

PoolBalances accrue_pools (PoolBalances balances, std::uint64_t reward)
{
    const auto shares = split_reward(reward);
    add_checked(balances.n_pool, shares.n_pool);
    add_checked(balances.z_pool, shares.z_pool);
    return balances;
}

std::uint64_t claim_n_pool (PoolBalances &balances, std::uint64_t requested) noexcept
{
    const auto paid = std::min(balances.n_pool, requested);
    balances.n_pool -= paid;
    return paid;
}

std::uint64_t claim_z_pool (PoolBalances &balances, std::uint64_t requested,
                            std::uint64_t collision_subsidy) noexcept
{
    const auto paid = std::min({balances.z_pool, requested, z_finder_cap(collision_subsidy)});
    balances.z_pool -= paid;
    return paid;
}

E46iSpend spend_e46i (std::uint64_t amount, std::uint64_t paid_height,
                      std::uint64_t spend_height)
{
    if (spend_height < paid_height || spend_height - paid_height < coinbase_maturity)
        throw std::invalid_argument("E46i coinbase output is not mature");
    const auto paid_epoch = paid_height / epoch_blocks;
    const auto spend_epoch = spend_height / epoch_blocks;
    const auto elapsed = spend_epoch - paid_epoch;
    const auto value = elapsed >= 64 ? 0 : amount >> elapsed;
    return {value, amount - value};
}
} // namespace e46::emission
