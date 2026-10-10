#include "e46/emission.hpp"
#include <charconv>
#include <cstdint>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>

namespace em = e46::emission;

namespace
{
std::uint64_t number (const std::string &text)
{
    std::uint64_t value{};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size())
        throw std::invalid_argument("invalid unsigned integer");
    return value;
}

void require_end (std::istringstream &in)
{
    std::string extra;
    if (in >> extra)
        throw std::invalid_argument("extra command fields");
}

std::string execute (const std::string &line)
{
    std::istringstream in(line);
    std::string op;
    in >> op;
    if (op == "reward")
    {
        std::string height;
        if (!(in >> height))
            throw std::invalid_argument("reward needs a block height");
        require_end(in);
        return std::to_string(em::reward_at(number(height)));
    }
    if (op == "split")
    {
        std::string reward_text;
        if (!(in >> reward_text))
            throw std::invalid_argument("split needs a reward");
        require_end(in);
        const auto shares = em::split_reward(number(reward_text));
        return std::to_string(shares.miner) + " " + std::to_string(shares.n_pool) + " " +
               std::to_string(shares.z_pool);
    }
    if (op == "ncap" || op == "zcap")
    {
        std::string subsidy;
        if (!(in >> subsidy))
            throw std::invalid_argument("cap needs a subsidy");
        require_end(in);
        const auto value = number(subsidy);
        return std::to_string(op == "ncap" ? em::n_stake_cap(value) : em::z_finder_cap(value));
    }
    if (op == "accrue")
    {
        std::string n, z, reward;
        if (!(in >> n >> z >> reward))
            throw std::invalid_argument("accrue needs N balance, Z balance and reward");
        require_end(in);
        const auto result = em::accrue_pools({number(n), number(z)}, number(reward));
        return std::to_string(result.n_pool) + " " + std::to_string(result.z_pool);
    }
    if (op == "claimn" || op == "claimz")
    {
        std::string balance, requested, subsidy;
        if (!(in >> balance >> requested))
            throw std::invalid_argument("claim needs balance and requested amount");
        const auto initial = number(balance);
        const auto wanted = number(requested);
        std::uint64_t paid{};
        std::uint64_t remaining{};
        if (op == "claimn")
        {
            require_end(in);
            em::PoolBalances pools{initial, 0};
            paid = em::claim_n_pool(pools, wanted);
            remaining = pools.n_pool;
        }
        else
        {
            if (!(in >> subsidy))
                throw std::invalid_argument("claimz needs a collision subsidy");
            require_end(in);
            em::PoolBalances pools{0, initial};
            paid = em::claim_z_pool(pools, wanted, number(subsidy));
            remaining = pools.z_pool;
        }
        return std::to_string(paid) + " " + std::to_string(remaining);
    }
    if (op == "e46i")
    {
        std::string amount, paid_height, spend_height;
        if (!(in >> amount >> paid_height >> spend_height))
            throw std::invalid_argument("e46i needs amount, paid height and spend height");
        require_end(in);
        const auto result = em::spend_e46i(number(amount), number(paid_height), number(spend_height));
        return std::to_string(result.spendable) + " " + std::to_string(result.burnt);
    }
    if (op == "sim")
    {
        std::string years_text;
        if (!(in >> years_text))
            throw std::invalid_argument("sim needs years");
        require_end(in);
        const auto years = number(years_text);
        if (years > 1000)
            throw std::invalid_argument("simulation limited to 1000 table-years");
        if (years > std::numeric_limits<std::uint64_t>::max() /
                        (em::epochs_per_table_year * em::epoch_blocks))
            throw std::overflow_error("simulation block count overflow");
        const auto blocks = years * em::epochs_per_table_year * em::epoch_blocks;
        const auto rewards = em::reward_epochs(years * em::epochs_per_table_year);
        std::uint64_t miner = 0, n_pool = 0, z_pool = 0, total = 0;
        for (std::uint64_t height = 0; height < blocks; ++height)
        {
            const auto reward = rewards[static_cast<std::size_t>(height / em::epoch_blocks)];
            const auto shares = em::split_reward(reward);
            if (shares.miner + shares.n_pool + shares.z_pool != reward)
                throw std::logic_error("per-block reward conservation failed");
            miner += shares.miner;
            n_pool += shares.n_pool;
            z_pool += shares.z_pool;
            total += reward;
        }
        return std::to_string(blocks) + " " + std::to_string(miner) + " " +
               std::to_string(n_pool) + " " + std::to_string(z_pool) + " " + std::to_string(total);
    }
    throw std::invalid_argument("unknown emission command");
}
} // namespace

int main ()
{
    std::string line;
    while (std::getline(std::cin, line))
    {
        try
        {
            std::cout << execute(line) << '\n';
        }
        catch (const std::exception &)
        {
            std::cout << "ERR\n";
        }
    }
}
