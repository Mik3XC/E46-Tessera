#include "e46/qtl_v2.hpp"
#include "hex.hpp"
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

using e46::rl::tool::hex;
using e46::rl::tool::unhex;
namespace q = e46::qtl_v2;

namespace
{
std::vector<std::uint8_t> field (const std::string &s) { return s == "-" ? std::vector<std::uint8_t>{} : unhex(s); }
std::uint32_t number (const char *s) { return static_cast<std::uint32_t>(std::stoul(s)); }
}

int main (int argc, char **argv)
{
    try
    {
        const std::string mode = argc > 1 ? argv[1] : "";
        std::string line;
        if (mode == "fingerprint" && argc == 2)
            while (std::getline(std::cin, line)) std::cout << hex(q::fingerprint(field(line))) << '\n';
        else if (mode == "step" && argc == 2)
            while (std::getline(std::cin, line)) std::cout << hex(q::chain_step(field(line))) << '\n';
        else if (mode == "lock-b" && argc == 3)
        {
            const auto steps = number(argv[2]);
            while (std::getline(std::cin, line)) std::cout << hex(q::lock_b_advance(field(line), steps)) << '\n';
        }
        else if (mode == "lock-a" && argc == 3)
        {
            const auto count = number(argv[2]);
            while (std::getline(std::cin, line))
            {
                std::istringstream in(line); std::string state, modulus; in >> state >> modulus;
                std::cout << hex(q::lock_a_advance(field(state), field(modulus), count)) << '\n';
            }
        }
        else if (mode == "checkpoint" && argc == 4)
        {
            if (std::string(argv[2]).size() != 1) throw std::invalid_argument("lock must be A or B");
            const char lock = argv[2][0]; const auto index = number(argv[3]);
            while (std::getline(std::cin, line)) std::cout << hex(q::checkpoint_commit(lock, index, field(line))) << '\n';
        }
        else if (mode == "password-check" && argc == 2)
            while (std::getline(std::cin, line))
            {
                std::istringstream in(line); std::string key, salt; in >> key >> salt;
                std::cout << hex(q::password_check(field(key), field(salt))) << '\n';
            }
        else if (mode == "final-key" && argc == 2)
            while (std::getline(std::cin, line))
            {
                std::istringstream in(line); std::string key, ya, yb; in >> key >> ya >> yb;
                std::cout << hex(q::final_key(field(key), field(ya), field(yb))) << '\n';
            }
        else if ((mode == "aes-encrypt" || mode == "aes-decrypt") && argc == 2)
            while (std::getline(std::cin, line))
            {
                std::istringstream in(line); std::string key, nonce, data, aad;
                in >> key >> nonce >> data >> aad;
                if (mode == "aes-encrypt")
                    std::cout << hex(q::aes256gcm_encrypt(field(key), field(nonce), field(data), field(aad))) << '\n';
                else
                    std::cout << hex(q::aes256gcm_decrypt(field(key), field(nonce), field(data), field(aad))) << '\n';
            }
        else if (mode == "argon2id" && argc == 5)
        {
            const auto memory = number(argv[2]), passes = number(argv[3]), lanes = number(argv[4]);
            while (std::getline(std::cin, line))
            {
                std::istringstream in(line); std::string credential, salt; in >> credential >> salt;
                std::cout << hex(q::argon2id(field(credential), field(salt), memory, passes, lanes)) << '\n';
            }
        }
        else
        {
            std::cerr << "Usage: qtl_v2_cli fingerprint|step|lock-a COUNT|lock-b COUNT|checkpoint A|B INDEX|password-check|final-key|aes-encrypt|aes-decrypt|argon2id MEM ITER LANES\n";
            return 2;
        }
        return 0;
    }
    catch (const std::exception &e) { std::cerr << "error: " << e.what() << '\n'; return 1; }
}
