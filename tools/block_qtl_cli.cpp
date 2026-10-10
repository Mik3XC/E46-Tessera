#include "e46/block_qtl.hpp"
#include "hex.hpp"
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

int main ()
{
    using namespace e46;
    std::string line;
    while (std::getline(std::cin, line))
    {
        try
        {
            const auto bytes = rl::tool::unhex(line);
            transaction::Output spent{};
            spent.type = 0x04;
            spent.payload.resize(32);
            transaction::SpentCoin coin{spent, false, 0};
            auto tx = transaction::deserialize(bytes, std::span(&coin, 1));
            const auto commitment = block_qtl::make_commitment(tx);
            std::cout << rl::tool::hex(commitment) << '\n';
        }
        catch (const std::exception &)
        {
            std::cout << "ERR\n";
        }
    }
}
