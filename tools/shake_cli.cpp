// WO-02 command-line driver for differential tests and the reviewer's surprise exam.
//   shake_cli shake <out_len>                  stdin: one hex message per line
//   shake_cli tagged <tag> <out_len>           stdin: one hex message per line
//   shake_cli stream <out_len> <chunk_bytes>   stdin: one hex message per line (incremental API)
//   shake_cli kmac <out_len> <custom_hex>      stdin: "<key_hex> <msg_hex>" per line ("-" = empty)
#include "e46/shake.hpp"
#include "hex.hpp"
#include <algorithm>
#include <iostream>
#include <sstream>
#include <string>

using e46::rl::tool::hex;
using e46::rl::tool::unhex;
namespace sh = e46::shake;

namespace
{
std::vector<std::uint8_t> field (const std::string &s)
{
    return s == "-" ? std::vector<std::uint8_t>{} : unhex(s);
}
std::size_t number (const char *s)
{
    return static_cast<std::size_t>(std::stoull(s));
}
} // namespace

int main (int argc, char **argv)
{
    try
    {
        const std::string mode = argc > 1 ? argv[1] : "";
        std::string line;
        if (mode == "shake" && argc == 3)
        {
            const auto L = number(argv[2]);
            while (std::getline(std::cin, line))
                std::cout << hex(sh::shake256(field(line), L)) << '\n';
        }
        else if (mode == "tagged" && argc == 4)
        {
            const auto L = number(argv[3]);
            while (std::getline(std::cin, line))
                std::cout << hex(sh::shake256_tagged(argv[2], field(line), L)) << '\n';
        }
        else if (mode == "stream" && argc == 4)
        {
            const auto L = number(argv[2]);
            const auto chunk = std::max<std::size_t>(1, number(argv[3]));
            while (std::getline(std::cin, line))
            {
                const auto m = field(line);
                sh::Shake256 h;
                for (std::size_t off = 0; off < m.size(); off += chunk)
                    h.update(sh::Bytes(m).subspan(off, std::min(chunk, m.size() - off)));
                std::cout << hex(h.finalize(L)) << '\n';
            }
        }
        else if (mode == "kmac" && argc == 4)
        {
            const auto L = number(argv[2]);
            const auto custom_bytes = field(argv[3]);
            const std::string custom(custom_bytes.begin(), custom_bytes.end());
            while (std::getline(std::cin, line))
            {
                std::istringstream in(line);
                std::string k, m;
                in >> k >> m;
                std::cout << hex(sh::kmac256(field(k), field(m), L, custom)) << '\n';
            }
        }
        else
        {
            std::cerr
                << "Usage: shake_cli shake L | tagged TAG L | stream L CHUNK | kmac L CUSTOMHEX\n";
            return 2;
        }
        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "error: " << e.what() << '\n';
        return 1;
    }
}
