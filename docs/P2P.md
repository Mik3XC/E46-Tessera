# Experimental testnet peers and rebuilding

This is protocol version **1**, network **1** (E46 testnet), with manual IPv4
peers. It is a local experiment implementation, not a public release or an
audited Internet service. Genesis, PoW, ASERT, transaction validation, cumulative
chainwork selection, and the height-268 checkpoint remain unchanged.

## Start a persistent node on macOS

From the repository root:

```sh
cmake --preset dev
cmake --build --preset dev
./build/dev/e46-node serve
```

The process stays in the foreground until `stop`, Ctrl-C, or SIGTERM. It owns the
chain state and exclusive datadir lock. Its default listener is
`127.0.0.1:19446`; its default datadir on macOS is:

```text
~/Library/Caches/E46Tessera
```

On Linux the default is `$XDG_CACHE_HOME/E46Tessera`, or
`~/.cache/E46Tessera` when that variable is unset. `--datadir DIR` overrides the
default on both platforms. Relative paths are resolved from the working directory.
The system can purge caches: use a durable explicit datadir for a long-lived
seed node. Keep wallets, recovery phrases, passwords and fingerprints outside
this cache. Existing `/private/tmp` stores are not automatically moved or changed.

`serve` needs the datadir path plus `/control.sock` to fit the operating system's
Unix-socket path limit (104 bytes on macOS, 108 on Linux) and refuses a longer path
with a clear message. One-shot commands such as `getblock` and `balance` work with
any datadir path.

In a second terminal:

```sh
./build/dev/e46-node status
./build/dev/e46-node snapshot 10
./build/dev/e46-node mempool
./build/dev/e46-node stop
```

Existing balance, submit, getblock, gettx, template and snapshot commands connect
to the running node's owner-only `DATADIR/control.sock`. The explorer bridge can
keep invoking `snapshot`. Its JSON reports `p2pEnabled: true` when served by the
daemon. No TCP wallet/RPC service is exposed. Without a daemon the ordinary
commands still run once and exit; another active writer prevents a cold start.

## Two terminals, two datadirs

Terminal A:

```sh
./build/dev/e46-node --datadir "$HOME/Library/Caches/E46Tessera/node-a" \
  serve --listen 127.0.0.1:19446
```

Terminal B:

```sh
./build/dev/e46-node --datadir "$HOME/Library/Caches/E46Tessera/node-b" \
  serve --listen 127.0.0.1:19447 --connect 127.0.0.1:19446
```

A fresh pair starts at genesis. To follow the historical testnet, one peer needs
the matching historical blocks or a connection to a peer holding them. There
are no bundled seeds or DNS discovery. Copy a stopped node's **blocks** directory
into an otherwise fresh datadir; do not copy wallets or a running control socket.

`--connect HOST:PORT` can be repeated. Configured connections are retried every
five seconds. Hostnames are resolved at startup; IPv6 is not implemented yet.
A node requests one successor at a time using a locator of known ancestors.
This supports catch-up across forks; each accepted block goes through consensus
validation, and cumulative work selects the active branch. A claimed height or
peer tip is never accepted as proof. Equal-work forks keep the existing tip.

Pending transaction inventory is exchanged after handshake and periodically.
A catching-up node waits until its peer reports no further blocks before
requesting pending transactions. Valid ordinary transactions are persisted and
relayed; accepted blocks announce the new tip. Mempool spends are revalidated
when the active tip changes. Ordinary spends disconnected in a reorg are
reconsidered. Invalid/conflicting spends are removed.

## Submit and mine while serving

```sh
E46_DATA="$HOME/Library/Caches/E46Tessera/node-a"
E46_ADDRESS='REPLACE_WITH_YOUR_TESTNET_ADDRESS'
E46_RAW=$(cat /path/to/public-signed-payment.tx.hex)
./build/dev/e46-node --datadir "$E46_DATA" submit "$E46_RAW"
./build/dev/e46-node --datadir "$E46_DATA" mine 1 "$E46_ADDRESS"
./build/dev/e46-node --datadir "$E46_DATA" status
./build/dev/e46-node --datadir "$E46_DATA" stop-mining
```

With a daemon, `mine` starts one background worker and returns immediately.
`status` reports the remaining block count. Consensus validation and state
changes stay on the event-loop thread. A changed active tip cancels and refreshes
mining work. Without a daemon, `mine` retains its synchronous CLI behavior.
`ACCEPTED` is mempool acceptance; confirm inclusion with `getblock HEIGHT`.

QTL peer admission does **not** launch commitment puzzle mining on behalf of an
untrusted sender. A relayed QTL spend requires an existing on-chain commitment;
ordinary payment relay is exercised by the integration script. QTL wallet
unlocking and Argon2 work are not a network RPC interface.

## Rebuild from local blocks

Stop the daemon first:

```sh
./build/dev/e46-node --datadir "$E46_DATA" stop
./build/dev/e46-node --datadir "$E46_DATA" rebuild
```

The current engine reconstructs its in-memory index, cumulative work, UTXOs,
reward pools, QTL commitments and tip from block records on **every startup**.
`rebuild` explicitly runs that same replay and reports the rebuilt height and
ID. It checks the frozen genesis, parent links, block filenames, PoW, ASERT,
transactions, commitments and checkpoint, then revalidates pending transactions.
There is no separate cached database to delete.

Missing ancestors or corrupted records stop replay with an error. Rebuilding
does not delete, skip, repair, or trust damaged blocks. A missing final suffix
cannot be detected from disk alone; a peer can supply it. To reconstruct from a
peer after corruption, retain the old store for inspection, choose a **new**
datadir, and start it with `--connect` to a valid peer. The fresh node downloads
and validates all blocks from genesis. This does not reconstruct private keys.

`import /path/to/BLOCK.blk` is a local administrative command. It accepts one
versioned block-store record, validates it normally, and announces an active-tip
change if serving. It is useful for replaying already-mined public fixtures.
There is no validation bypass and no checkpoint bypass.

## Bounds and scope

| Resource | Bound |
| --- | --- |
| Peer sockets | Default 8; `--max-peers` 1–16, including configured outbound peers |
| Local control clients | 4; socket permissions 0600 |
| Block record | 4,100,000 bytes (existing store format limit) |
| Transaction bytes | 4,000,000 plus 32-byte ID in a peer message |
| Locators / transaction inventory | 80 / 1,000 identifiers |
| Peer input / output | One maximum frame / approximately 8.2 MB |
| Local control frame | Less than 16 MiB including header |
| Handshake / partial frame / stalled output | 10 / 30 / 30 seconds |
| Block or transaction response / idle socket | 30 / 60 seconds |
| Message budget | 256-frame burst, refilling 128 frames/second per connection |
| Incoming block/transaction validation admission | One at a time; at least 25 ms between starts globally |
| Outstanding requests per peer | One block and one transaction |
| Mempool | 1,000 transactions / 64 MiB |
| Stored blocks in daemon experiment | 4,096 including side branches |
| Disk floor | Existing 1 GiB minimum free space |

Types and declared lengths are checked before waiting for an entire frame.
Malformed/unexpected traffic closes the connection. No unbounded orphan queue
is maintained. Validation admission limits frequency; it does not interrupt an
individual cryptographic check. Valid maximum-size blocks can still take time.

The existing engine retains a UTXO snapshot per block, so memory grows much
faster than a production chain database. The experimental block-count ceiling
is a transport/daemon safeguard, not a consensus rule or a memory guarantee.
Before an unrestricted public seed, improve state storage, benchmark adversarial
validation costs, and review connection admission/peer diversity. This version
has no transport encryption, peer authentication, address gossip, bans persisted
across reconnects, automatic discovery, or public RPC.

**Measured cost of one peer message (independent review, 12 Oct 2026).** On a
274-block chain, one INVENTORY frame naming 1,000 unknown transaction IDs delays
every other event-loop task by about 0.3 s, because each ID rescans the active
chain and rehashes its transactions. Eight peers sending one frame each at the same
moment delay it by about 2.2 s. The cost grows with chain length. A single connection
cannot repeat it, because its pending-ID list is capped at 1,000 and drains slowly.
This is acceptable for a loopback testnet and must be fixed before any public
listener, for example with a transaction-ID index, or one known-ID set built per
message.

## NAT and later hosting

For outbound peers, a home node needs only the remote peer's reachable address.
It does not need to advertise its own public IP. To accept inbound connections,
listen explicitly on the desired interface and arrange router/firewall access.
A WAN address behind carrier-grade NAT is not directly reachable by ordinary
port forwarding. A VPS with a reachable TCP port is an alternative seed.

Port **19446 is an experimental local convention**, not an IANA allocation.
Public bind, firewall/router changes, VPS purchase, service installation and
public deployment are separate operator actions. This task does not change them.
Pi and Orange Pi builds remain pending identification of the board and OS;
`uname -m` on each device identifies the installed architecture.

## Reproduce the checks

Standard-library Python only. The script uses independent cache datadirs,
localhost ports and child daemons, and stops the daemons on exit. It retains its
logs and public records in the printed experiment directory for inspection.

Basic handshake/control exercise without historical fixtures:

```sh
python3 tests/p2p_integration.py --node build/dev/e46-node
```

Complete historical payment exercise:

```sh
python3 tests/p2p_integration.py --node build/dev/e46-node \
  --chain /path/to/historical-testnet-datadir \
  --payment /path/to/public-signed-first-payment.tx.hex
```

It expects the canonical public block records 0–269 and the signed first-payment
bytes. No wallet, private seed or password is needed or copied. No GOLD bundle
is included. Add `--mine-real` to also wait up to 30 minutes for one newly mined
block and verify that a second node receives the same validated tip. Mining
uses the unchanged consensus target; runtime depends on hardware and luck.

See [the recorded local exercise](P2P-EXERCISE.md) for what was actually run.
