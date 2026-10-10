#include "e46/rl.hpp"
#include "hex.hpp"
#include "rl_detail.hpp"
#include <algorithm>
#include <charconv>
#include <iostream>
#include <sstream>
#include <string>

using namespace e46::rl;
namespace
{
std::uint64_t number (const std::string &s)
{
    std::uint64_t out = 0;
    const auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), out);
    if (ec != std::errc{} || p != s.data() + s.size())
        throw std::invalid_argument("Expected unsigned integer");
    return out;
}
} // namespace
int main (int argc, char **argv)
{
    try
    {
        if (argc == 2 && std::string_view(argv[1]) == "step")
        {
            std::string line;
            while (std::getline(std::cin, line))
            {
                std::istringstream in(line);
                std::string s;
                std::array<std::uint64_t, 10> words{};
                for (auto &word : words)
                {
                    if (!(in >> s))
                        throw std::invalid_argument("Missing step word");
                    word = number(s);
                }
                if (in >> s)
                    throw std::invalid_argument("Extra step word");
                if (words[0] > UINT64_MAX - 64 || words[1] > 1)
                    throw std::invalid_argument("Invalid counter or bit");
                detail::Words x{}, v{};
                std::copy_n(words.begin() + 2, 4, x.begin());
                std::copy_n(words.begin() + 6, 4, v.begin());
                detail::step(x, v, words[0], words[1] != 0);
                std::cout << tool::hex(detail::output(x, v).unfolded) << '\n';
            }
            return 0;
        }
        if (argc < 3 || argc > 4)
            throw std::invalid_argument(
                "Usage: rl_cli v2|v3 one|stream [chunk_bytes]; or rl_cli step");
        const std::string_view v = argv[1], mode = argv[2];
        if (v != "v2" && v != "v3")
            throw std::invalid_argument("Unknown version");
        if (mode != "one" && mode != "stream")
            throw std::invalid_argument("Unknown mode");
        const auto chunk = argc == 4 ? number(argv[3]) : 7;
        if (chunk == 0)
            throw std::invalid_argument("Chunk must be positive");
        std::string line;
        while (std::getline(std::cin, line))
        {
            const auto message = tool::unhex(line);
            Result result{};
            if (mode == "one")
            {
                result = v == "v3" ? Result{rl_v3_128(message), rl_v3_unfolded(message)}
                                   : Result{rl_v2_128(message), rl_v2_unfolded(message)};
            }
            else
            {
                Hasher h(message.size(), v == "v3" ? Version::v3 : Version::v2);
                for (std::size_t p = 0; p < message.size();)
                {
                    const auto count = static_cast<std::size_t>(
                        std::min<std::uint64_t>(chunk, message.size() - p));
                    h.update(Bytes(message).subspan(p, count));
                    p += count;
                }
                result = h.finalize();
            }
            std::cout << tool::hex(result.folded) << ' ' << tool::hex(result.unfolded) << '\n';
        }
        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << '\n';
        return 2;
    }
}
