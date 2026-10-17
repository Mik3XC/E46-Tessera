#include "e46/p2p.hpp"
#include "e46/addresses.hpp"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netdb.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/rand.h>
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <deque>
#include <iostream>
#include <sstream>
#include <thread>
#include <utility>

namespace e46::p2p
{
namespace
{
using Bytes = std::vector<std::uint8_t>;
using Clock = std::chrono::steady_clock;
using Time = Clock::time_point;
constexpr std::size_t wire_limit = 4'100'032;
constexpr std::size_t control_limit = 16 * 1024 * 1024;
constexpr std::size_t queue_limit = 2 * wire_limit + 4096;
constexpr std::uint32_t hello = 1, getblock = 2, block = 3, tip = 4,
    inventory = 5, gettx = 6, tx = 7, notfound = 8, command = 100, result = 101, failure = 102;
volatile std::sig_atomic_t interrupted = 0;
void signal_stop(int) { interrupted = 1; }
void require(bool ok, const char *why) { if (!ok) throw std::runtime_error(why); }
struct Socket
{
    int fd = -1;
    Socket() = default;
    explicit Socket(int value) : fd(value) {}
    ~Socket() { if (fd >= 0) ::close(fd); }
    Socket(Socket &&other) noexcept : fd(std::exchange(other.fd, -1)) {}
    Socket &operator=(Socket &&other) noexcept
    {
        if (this != &other) { if (fd >= 0) ::close(fd); fd = std::exchange(other.fd, -1); }
        return *this;
    }
    Socket(const Socket &) = delete;
};
void nonblocking(int fd)
{
    require(::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL, 0) | O_NONBLOCK) == 0, "Cannot set nonblocking socket");
    require(::fcntl(fd, F_SETFD, FD_CLOEXEC) == 0, "Cannot set socket close-on-exec");
}
std::uint32_t u32(const std::uint8_t *p)
{
    return (std::uint32_t(p[0]) << 24) | (std::uint32_t(p[1]) << 16) | (std::uint32_t(p[2]) << 8) | p[3];
}
void put32(Bytes &out, std::uint32_t n)
{
    for (int i = 3; i >= 0; --i) out.push_back(static_cast<std::uint8_t>(n >> (8 * i)));
}
void append(Bytes &out, e46::shake::Bytes data) { out.insert(out.end(), data.begin(), data.end()); }
node::Digest digest(e46::shake::Bytes bytes)
{
    require(bytes.size() == 32, "Expected 32-byte identifier");
    node::Digest id{}; std::copy(bytes.begin(), bytes.end(), id.begin()); return id;
}
Bytes frame(std::uint32_t type, e46::shake::Bytes payload)
{
    Bytes out{'E','4','6','P'}; put32(out, type); put32(out, static_cast<std::uint32_t>(payload.size())); append(out, payload); return out;
}
// A Unix socket path is limited (104 bytes on macOS, 108 on Linux).
bool control_path_fits(const std::filesystem::path &directory)
{
    sockaddr_un probe{};
    return (std::filesystem::absolute(directory) / "control.sock").string().size() < sizeof(probe.sun_path);
}
sockaddr_un local_address(const std::filesystem::path &directory)
{
    sockaddr_un address{}; address.sun_family = AF_UNIX;
    require(control_path_fits(directory), "Datadir path too long for the local control socket");
    const auto path = (std::filesystem::absolute(directory) / "control.sock").string();
    std::copy(path.begin(), path.end(), address.sun_path); return address;
}
sockaddr_in endpoint(const std::string &value)
{
    const auto colon = value.rfind(':');
    require(colon != std::string::npos && colon > 0, "Endpoint must be IPv4-or-hostname:port");
    const auto host = value.substr(0, colon), port = value.substr(colon + 1);
    require(!port.empty() && port.size() <= 5 && std::all_of(port.begin(), port.end(), ::isdigit), "Invalid peer port");
    const auto n = std::stoul(port); require(n > 0 && n <= 65535, "Peer port outside 1..65535");
    addrinfo hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    addrinfo *resolved = nullptr;
    require(::getaddrinfo(host.c_str(), port.c_str(), &hints, &resolved) == 0, "Cannot resolve configured endpoint");
    const auto address = *reinterpret_cast<sockaddr_in *>(resolved->ai_addr);
    ::freeaddrinfo(resolved); return address;
}
Socket listener(const sockaddr *address, socklen_t length, int family)
{
    Socket socket(::socket(family, SOCK_STREAM, 0)); require(socket.fd >= 0, "Cannot create listener");
    int one = 1;
    ::setsockopt(socket.fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    require(::bind(socket.fd, address, length) == 0, "Cannot bind listener (address busy or permissions)");
    require(::listen(socket.fd, 16) == 0, "Cannot listen"); nonblocking(socket.fd); return socket;
}
struct Peer
{
    Socket socket;
    bool local = false, connecting = false, ready = false, closing = false, dead = false;
    std::string target;
    Bytes input, output;
    std::size_t sent = 0;
    Time born = Clock::now(), received = born, write_start = born, frame_start = born, polled = born;
    double tokens = 256;
    Time refill = born;
    bool block_pending = false, synced = false;
    Time requested = born;
    std::optional<node::Digest> cursor, wanted_tx;
    Time tx_requested = born;
    std::deque<node::Digest> wanted;
    std::array<std::uint8_t, 8> remote_nonce{};
    explicit Peer(Socket socket_, bool local_ = false) : socket(std::move(socket_)), local(local_) {}
    void queue(std::uint32_t type, e46::shake::Bytes bytes)
    {
        const auto cap = local ? control_limit : queue_limit;
        require(bytes.size() <= (local ? control_limit - 12 : wire_limit), "Response exceeds transport limit");
        if (sent) { output.erase(output.begin(), output.begin() + static_cast<std::ptrdiff_t>(sent)); sent = 0; }
        require(output.size() + bytes.size() + 12 <= cap, "Peer output queue full");
        if (output.empty()) write_start = Clock::now();
        append(output, frame(type, bytes));
    }
};
std::vector<std::string> parse_command(const Bytes &bytes)
{
    require(std::find(bytes.begin(), bytes.end(), 0) == bytes.end(), "NUL in command");
    std::istringstream stream(std::string(bytes.begin(), bytes.end()));
    std::vector<std::string> args; std::string line;
    while (std::getline(stream, line)) { require(args.size() < 8, "Too many command arguments"); args.push_back(line); }
    require(!args.empty(), "Empty command"); return args;
}
void queue_text(Peer &peer, std::uint32_t type, const std::string &text)
{
    peer.queue(type, {reinterpret_cast<const std::uint8_t *>(text.data()), text.size()});
}
}

std::optional<std::string> request(const std::filesystem::path &directory, const std::vector<std::string> &args)
{
    // No daemon can listen on a path that does not fit (serve refuses it), so
    // this is the "no daemon" case. Throwing here made every ordinary one-shot
    // command fail for long datadir paths, with or without a daemon.
    if (!control_path_fits(directory)) return {};
    const auto address = local_address(directory);
    Socket socket(::socket(AF_UNIX, SOCK_STREAM, 0)); require(socket.fd >= 0, "Cannot create control socket");
    if (::connect(socket.fd, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0)
    {
        if (errno == ENOENT || errno == ECONNREFUSED) return {};
        throw std::runtime_error("Cannot connect to local daemon");
    }
    nonblocking(socket.fd);
    std::string text;
    for (const auto &arg : args) { require(arg.find_first_of("\n\r") == std::string::npos, "Newline in command argument"); text += arg + '\n'; }
    require(text.size() <= control_limit - 12, "Control command too large");
    const auto out = frame(command, {reinterpret_cast<const std::uint8_t *>(text.data()), text.size()});
    Bytes input; std::size_t sent = 0;
    const auto deadline = Clock::now() + std::chrono::seconds(60);
    while (Clock::now() < deadline)
    {
        pollfd fd{socket.fd, static_cast<short>(POLLIN | (sent < out.size() ? POLLOUT : 0)), 0};
        if (::poll(&fd, 1, 100) < 0 && errno != EINTR) throw std::runtime_error("Control poll failed");
        if (fd.revents & POLLOUT)
        {
            const auto n = ::send(socket.fd, out.data() + sent, out.size() - sent, 0);
            if (n > 0) sent += static_cast<std::size_t>(n);
            else if (n < 0 && errno != EAGAIN && errno != EINTR) throw std::runtime_error("Control send failed");
        }
        if (fd.revents & (POLLIN | POLLHUP))
        {
            std::array<std::uint8_t, 65536> chunk{};
            const auto n = ::recv(socket.fd, chunk.data(), chunk.size(), 0);
            require(n != 0, "Daemon closed control connection");
            if (n > 0) append(input, {chunk.data(), static_cast<std::size_t>(n)});
            else if (errno != EAGAIN && errno != EINTR) throw std::runtime_error("Control receive failed");
        }
        if (input.size() >= 12)
        {
            require(std::equal(input.begin(), input.begin() + 4, "E46P"), "Invalid control frame");
            const auto length = u32(input.data() + 8), type = u32(input.data() + 4);
            require(length <= control_limit - 12, "Control response too large");
            if (input.size() >= 12 + length)
            {
                const std::string answer(input.begin() + 12, input.begin() + 12 + length);
                if (type == failure) throw std::runtime_error(answer);
                require(type == result, "Invalid control response type"); return answer;
            }
        }
        if (fd.revents & (POLLERR | POLLNVAL)) throw std::runtime_error("Control socket failed");
    }
    throw std::runtime_error("Local daemon response timed out; command outcome may be unknown");
}

void serve(node::Node &node, const std::filesystem::path &directory, const Options &options, const Command &handler)
{
    require(options.max_peers >= 1 && options.max_peers <= 16, "max-peers must be 1..16");
    require(options.connect.size() <= options.max_peers, "More configured peers than connection slots");
    interrupted = 0;
    const auto old_int = std::signal(SIGINT, signal_stop), old_term = std::signal(SIGTERM, signal_stop);
    const auto old_pipe = std::signal(SIGPIPE, SIG_IGN);
    struct Cleanup
    {
        std::filesystem::path socket;
        bool owns_socket = false;
        void (*sigint)(int);
        void (*sigterm)(int);
        void (*sigpipe)(int);
        ~Cleanup() { std::error_code ec; if (owns_socket) std::filesystem::remove(socket, ec); std::signal(SIGINT, sigint); std::signal(SIGTERM, sigterm); std::signal(SIGPIPE, sigpipe); }
    } cleanup{directory / "control.sock", false, old_int, old_term, old_pipe};
    const auto tcp_address = endpoint(options.listen);
    auto tcp = listener(reinterpret_cast<const sockaddr *>(&tcp_address), sizeof(tcp_address), AF_INET);
    const auto address = local_address(directory);
    // Safe stale-socket cleanup is guarded by the caller's exclusive datadir lock.
    struct stat st{};
    if (::lstat(address.sun_path, &st) == 0)
    {
        require(S_ISSOCK(st.st_mode) && st.st_uid == ::geteuid(), "Control path exists and is not our socket");
        require(::unlink(address.sun_path) == 0, "Cannot remove stale control socket");
    }
    const auto mask = ::umask(0077);
    Socket local;
    try { local = listener(reinterpret_cast<const sockaddr *>(&address), sizeof(address), AF_UNIX); }
    catch (...) { ::umask(mask); throw; }
    ::umask(mask);
    cleanup.owns_socket = true;
    std::vector<std::pair<std::string, sockaddr_in>> targets;
    for (const auto &target : options.connect)
    {
        require(std::none_of(targets.begin(), targets.end(), [&](const auto &item) { return item.first == target; }), "Duplicate --connect endpoint");
        targets.emplace_back(target, endpoint(target));
    }
    std::array<std::uint8_t, 8> nonce{};
    require(RAND_bytes(nonce.data(), nonce.size()) == 1, "Cannot create handshake nonce");
    const auto genesis = node.get_block(std::uint64_t{0}).id;
    Bytes greeting; put32(greeting, 1); put32(greeting, 1); append(greeting, genesis); append(greeting, nonce); append(greeting, node.tip_id());
    std::vector<Peer> peers;
    peers.reserve(options.max_peers + 4);
    auto last_connect = Clock::now() - std::chrono::seconds(10);
    std::uint64_t accepted_blocks = 0, accepted_txs = 0, rejected = 0;
    std::atomic<bool> mine_done{false};
    node::Block mining_block{};
    std::uint64_t mining_remaining = 0;
    node::AddressPayload mining_address{};
    // Declared last: join before any data referenced by the worker is destroyed.
    std::jthread miner;
    auto start_miner = [&] {
        mining_block = node.block_template(mining_address);
        mine_done.store(false);
        miner = std::jthread([&](std::stop_token stop) {
            if (node::Node::solve(mining_block, stop)) mine_done.store(true, std::memory_order_release);
        });
    };
    auto announce = [&](std::uint32_t type, e46::shake::Bytes payload, int except = -1) {
        for (auto &peer : peers) if (!peer.local && peer.ready && !peer.dead && peer.socket.fd != except)
        {
            try { peer.queue(type, payload); } catch (const std::exception &) { peer.dead = true; }
        }
    };
    auto announce_pool = [&] {
        Bytes ids; for (const auto &id : node.mempool_txids()) append(ids, id);
        announce(inventory, ids);
    };
    auto sync = [&](Peer &peer) {
        if (peer.block_pending) return;
        Bytes ids; for (const auto &id : node.locator(peer.cursor)) append(ids, id);
        peer.queue(getblock, ids); peer.synced = false; peer.block_pending = true; peer.requested = Clock::now();
    };
    auto next_tx = [&](Peer &peer) {
        if (!peer.synced || peer.block_pending) return;
        while (!peer.wanted_tx && !peer.wanted.empty())
        {
            const auto id = peer.wanted.front(); peer.wanted.pop_front();
            if (node.has_transaction(id)) continue;
            peer.wanted_tx = id; peer.tx_requested = Clock::now(); peer.queue(gettx, id);
        }
    };
    auto accepted_tip = [&] {
        announce(tip, node.tip_id()); announce_pool();
        if (mining_remaining && miner.joinable()) { miner.request_stop(); miner.join(); start_miner(); }
    };
    auto last_validation = Clock::now() - std::chrono::seconds(1);
    bool stopping = false;
    Time stop_deadline{};
    std::cerr << "Serving E46 testnet on " << options.listen << " height " << node.height()
              << " datadir " << directory << '\n';
    while (!interrupted)
    {
        const auto now = Clock::now();
        if (stopping && now >= stop_deadline) break;
        if (mine_done.load(std::memory_order_acquire))
        {
            miner.join();
            mine_done.store(false);
            try
            {
                const auto info = node.import_record(node::encode_record(mining_block));
                ++accepted_blocks; --mining_remaining;
                std::cerr << "Mined height " << info.height << '\n';
                accepted_tip();
            }
            catch (const std::exception &error) { std::cerr << "Mining acceptance: " << error.what() << '\n'; mining_remaining = 0; }
            if (mining_remaining) start_miner();
        }
        if (!stopping && now - last_connect >= std::chrono::seconds(5))
        {
            last_connect = now;
            for (const auto &[name, remote] : targets)
            {
                if (std::any_of(peers.begin(), peers.end(), [&](const auto &p) { return !p.dead && p.target == name; })) continue;
                if (static_cast<std::size_t>(std::count_if(peers.begin(), peers.end(), [](const auto &p) { return !p.local && !p.dead; })) >= options.max_peers) break;
                Socket socket(::socket(AF_INET, SOCK_STREAM, 0)); if (socket.fd < 0) continue;
                nonblocking(socket.fd);
                const auto status = ::connect(socket.fd, reinterpret_cast<const sockaddr *>(&remote), sizeof(remote));
                if (status != 0 && errno != EINPROGRESS) continue;
                peers.emplace_back(std::move(socket)); auto &peer = peers.back();
                peer.target = name; peer.connecting = status != 0; peer.queue(hello, greeting);
            }
        }
        std::vector<pollfd> fds{{tcp.fd, POLLIN, 0}, {local.fd, POLLIN, 0}};
        for (const auto &peer : peers)
            fds.push_back({peer.socket.fd, static_cast<short>((peer.closing ? 0 : POLLIN) | (peer.connecting || peer.sent < peer.output.size() ? POLLOUT : 0)), 0});
        if (::poll(fds.data(), fds.size(), 25) < 0 && errno != EINTR) throw std::runtime_error("Daemon poll failed");
        const auto polled_count = peers.size();
        for (std::size_t i = 0; i < polled_count; ++i)
        {
            auto &peer = peers[i];
            if (peer.dead) continue;
            try
            {
                const auto events = fds[i + 2].revents;
                if (events & (POLLERR | POLLNVAL)) throw std::runtime_error("Socket error");
                if (peer.connecting && events & POLLOUT)
                {
                    int error = 0; socklen_t size = sizeof(error);
                    require(::getsockopt(peer.socket.fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0 && error == 0, "Connect failed");
                    peer.connecting = false;
                }
                if (!peer.connecting && events & POLLOUT && peer.sent < peer.output.size())
                {
                    const auto count = ::send(peer.socket.fd, peer.output.data() + peer.sent, std::min<std::size_t>(65536, peer.output.size() - peer.sent), 0);
                    if (count > 0) peer.sent += static_cast<std::size_t>(count);
                    else if (count < 0 && errno != EAGAIN && errno != EINTR) throw std::runtime_error("Send failed");
                    if (peer.sent == peer.output.size()) { peer.output.clear(); peer.sent = 0; if (peer.closing) peer.dead = true; }
                }
                if (!peer.closing && events & (POLLIN | POLLHUP))
                {
                    std::array<std::uint8_t, 65536> buffer{};
                    const auto cap = peer.local ? control_limit : wire_limit + 12;
                    require(peer.input.size() < cap, "Peer input queue full");
                    const auto count = ::recv(peer.socket.fd, buffer.data(), std::min(buffer.size(), cap - peer.input.size()), 0);
                    require(count != 0, "Peer disconnected");
                    if (count > 0)
                    {
                        if (peer.input.empty()) peer.frame_start = now;
                        append(peer.input, {buffer.data(), static_cast<std::size_t>(count)}); peer.received = now;
                    }
                    else if (errno != EAGAIN && errno != EINTR) throw std::runtime_error("Receive failed");
                }
                require(peer.ready || now - peer.born < std::chrono::seconds(10), "Handshake/command timeout");
                require(peer.input.empty() || now - peer.frame_start < std::chrono::seconds(30), "Frame timeout");
                require(peer.output.empty() || now - peer.write_start < std::chrono::seconds(30), "Slow reader timeout");
                require(now - peer.received < std::chrono::seconds(60), "Idle peer timeout");
                require(!peer.block_pending || now - peer.requested < std::chrono::seconds(30), "Block response timeout");
                require(!peer.wanted_tx || now - peer.tx_requested < std::chrono::seconds(30), "Transaction response timeout");
                if (!peer.local && peer.ready && now - peer.polled >= std::chrono::seconds(10))
                {
                    peer.polled = now; sync(peer);
                    Bytes ids; for (const auto &id : node.mempool_txids()) append(ids, id); peer.queue(inventory, ids);
                }
                if (peer.input.size() < 12 || peer.closing) continue;
                require(std::equal(peer.input.begin(), peer.input.begin() + 4, "E46P"), "Wrong network frame magic");
                const auto type = u32(peer.input.data() + 4), length = u32(peer.input.data() + 8);
                std::size_t maximum = 0;
                if (peer.local) { require(type == command, "Invalid local command type"); maximum = control_limit - 12; }
                else
                {
                    require((!peer.ready && type == hello) || (peer.ready && type >= getblock && type <= notfound), "Handshake required / invalid message type");
                    switch (type)
                    {
                        case hello: maximum = 80; break;
                        case getblock: maximum = 80 * 32; break;
                        case block: maximum = 4'100'000; break;
                        case tip: case gettx: case notfound: maximum = 32; break;
                        case inventory: maximum = 1000 * 32; break;
                        case tx: maximum = 4'000'032; break;
                    }
                }
                require(length <= maximum, "Message exceeds type size limit");
                if (peer.input.size() < 12 + length) continue;
                if (!peer.local && (type == block || type == tx) && now - last_validation < std::chrono::milliseconds(25)) continue;
                peer.tokens = std::min(256.0, peer.tokens + std::chrono::duration<double>(now - peer.refill).count() * 128);
                peer.refill = now; require(peer.tokens >= 1, "Message rate exceeded"); peer.tokens -= 1;
                Bytes data(peer.input.begin() + 12, peer.input.begin() + 12 + length);
                peer.input.erase(peer.input.begin(), peer.input.begin() + 12 + length); peer.frame_start = now;
                if (peer.local)
                {
                    try
                    {
                        const auto args = parse_command(data);
                        std::string response;
                        if (args[0] == "status" && args.size() == 1)
                        {
                            const auto count = std::count_if(peers.begin(), peers.end(), [](const auto &p) { return !p.local && p.ready && !p.dead; });
                            response = "height " + std::to_string(node.height()) + "\npeers " + std::to_string(count) + "\naccepted_blocks " + std::to_string(accepted_blocks) + "\naccepted_transactions " + std::to_string(accepted_txs) + "\nrejected " + std::to_string(rejected) + "\nmining_remaining " + std::to_string(mining_remaining) + "\n";
                        }
                        else if (args[0] == "stop" && args.size() == 1)
                        {
                            stopping = true; stop_deadline = now + std::chrono::milliseconds(500); response = "STOPPING\n";
                        }
                        else if (args[0] == "mine" && args.size() == 3)
                        {
                            require(mining_remaining == 0, "Mining already active; use stop-mining first");
                            require(!args[1].empty() && args[1].size() < 5 && std::all_of(args[1].begin(), args[1].end(), ::isdigit), "Mining count must be 1..1000");
                            const auto count = std::stoull(args[1]); require(count >= 1 && count <= 1000, "Mining count must be 1..1000");
                            mining_address = addresses::decode_single_owner_address(args[2], addresses::Network::testnet);
                            mining_remaining = count;
                            try { start_miner(); } catch (...) { mining_remaining = 0; throw; }
                            response = "MINING " + std::to_string(count) + " blocks asynchronously; use status\n";
                        }
                        else if (args[0] == "stop-mining" && args.size() == 1)
                        {
                            miner.request_stop(); if (miner.joinable()) miner.join(); mine_done.store(false); mining_remaining = 0; response = "MINING STOPPED\n";
                        }
                        else
                        {
                            require(args[0] != "serve" && args[0] != "rebuild", "Stop the daemon before rebuilding");
                            const auto before = node.tip_id();
                            response = handler(args);
                            if (args[0] == "submit") { ++accepted_txs; announce_pool(); }
                            if (args[0] == "import") { ++accepted_blocks; }
                            if (node.tip_id() != before) accepted_tip();
                        }
                        queue_text(peer, result, response);
                    }
                    catch (const std::exception &error) { queue_text(peer, failure, error.what()); }
                    peer.ready = true; peer.closing = true; continue;
                }
                if (type == hello)
                {
                    require(data.size() == 80 && u32(data.data()) == 1 && u32(data.data() + 4) == 1, "Protocol version/network mismatch");
                    require(digest(e46::shake::Bytes(data).subspan(8, 32)) == genesis, "Genesis mismatch");
                    std::copy_n(data.begin() + 40, 8, peer.remote_nonce.begin());
                    require(peer.remote_nonce != nonce, "Self connection");
                    peer.ready = true; sync(peer);
                    Bytes ids; for (const auto &id : node.mempool_txids()) append(ids, id); peer.queue(inventory, ids);
                }
                else if (type == getblock)
                {
                    require(!data.empty() && data.size() % 32 == 0, "Invalid block locator");
                    std::vector<node::Digest> ids;
                    for (std::size_t n = 0; n < data.size(); n += 32) ids.push_back(digest(e46::shake::Bytes(data).subspan(n, 32)));
                    const auto next = node.next_after(ids);
                    if (next) peer.queue(block, node.block_record(*next)); else peer.queue(notfound, {});
                }
                else if (type == block)
                {
                    require(peer.block_pending && data.size() >= 128, "Unsolicited/truncated block");
                    const auto id = addresses::block_id(e46::shake::Bytes(data).subspan(8, 120));
                    if (!node.has_block(id))
                    {
                        last_validation = now;  // only real validation work takes the global slot
                        node.check_peer_block(data);  // no cheap side branches filling the store
                        const auto before = node.tip_id();
                        node.import_record(data); ++accepted_blocks;
                        if (node.tip_id() != before) accepted_tip();
                    }
                    peer.cursor = id; peer.block_pending = false; sync(peer);
                }
                else if (type == tip)
                {
                    const auto id = digest(data); if (!node.has_block(id)) sync(peer);
                }
                else if (type == inventory)
                {
                    require(data.size() % 32 == 0, "Invalid transaction inventory");
                    for (std::size_t n = 0; n < data.size() && peer.wanted.size() < 1000; n += 32)
                    {
                        const auto id = digest(e46::shake::Bytes(data).subspan(n, 32));
                        if (!node.has_transaction(id) && peer.wanted_tx != id && std::find(peer.wanted.begin(), peer.wanted.end(), id) == peer.wanted.end()) peer.wanted.push_back(id);
                    }
                    next_tx(peer);
                }
                else if (type == gettx)
                {
                    const auto id = digest(data);
                    const auto pending = node.mempool_txids();
                    if (std::find(pending.begin(), pending.end(), id) == pending.end()) peer.queue(notfound, id);
                    else
                    {
                        Bytes payload; append(payload, id); append(payload, transaction::serialize(*node.get_transaction(id))); peer.queue(tx, payload);
                    }
                }
                else if (type == tx)
                {
                    require(data.size() > 32, "Truncated transaction");
                    const auto id = digest(e46::shake::Bytes(data).first(32));
                    require(peer.wanted_tx == id, "Unsolicited transaction");
                    if (!node.has_transaction(id))
                    {
                        last_validation = now;  // only real validation work takes the global slot
                        node.submit_relay(e46::shake::Bytes(data).subspan(32), id); ++accepted_txs; announce(inventory, id, peer.socket.fd);
                    }
                    peer.wanted_tx.reset(); next_tx(peer);
                }
                else if (type == notfound)
                {
                    if (data.empty()) { require(peer.block_pending, "Unexpected sync completion"); peer.block_pending = false; peer.synced = true; next_tx(peer); }
                    else { require(peer.wanted_tx == digest(data), "Unexpected missing transaction"); peer.wanted_tx.reset(); next_tx(peer); }
                }
            }
            catch (const std::exception &error)
            {
                ++rejected; peer.dead = true;
                std::cerr << "Peer closed: " << error.what() << '\n';
            }
        }
        peers.erase(std::remove_if(peers.begin(), peers.end(), [](const auto &p) { return p.dead; }), peers.end());
        if (!stopping) for (std::size_t index = 0; index < 2; ++index)
        {
            if (!(fds[index].revents & POLLIN)) continue;
            Socket socket(::accept(fds[index].fd, nullptr, nullptr)); if (socket.fd < 0) continue;
            const bool is_local = index == 1;
            const auto count = std::count_if(peers.begin(), peers.end(), [&](const auto &p) { return p.local == is_local; });
            if (static_cast<std::size_t>(count) >= (is_local ? 4 : options.max_peers)) continue;
            nonblocking(socket.fd); peers.emplace_back(std::move(socket), is_local);
            if (!is_local) peers.back().queue(hello, greeting);
        }
    }
    miner.request_stop(); if (miner.joinable()) miner.join();
    std::cerr << "Node stopped at height " << node.height() << '\n';
}
} // namespace e46::p2p
