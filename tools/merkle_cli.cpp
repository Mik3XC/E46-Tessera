#include "merkle_protocol.hpp"
#include <iostream>

int main ()
{
    try
    {
        for (std::string line; std::getline(std::cin, line);)
        {
            try
            {
                const auto result = e46::merkle::tool::dispatch(line);
                std::cout << result << '\n';
            }
            catch (const std::invalid_argument &)
            {
                std::cout << "ERR\n";
            }
        }
    }
    catch (const std::exception &error)
    {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
