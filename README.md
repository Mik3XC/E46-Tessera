# E46 Tessera

Experimental C++ node and command-line wallet for the E46 development testnet.

Tessera implements a local proof-of-work chain, signed transactions, persistent
pending transactions, and a JSON snapshot interface for explorers. Refracting
Light v3 supplies the experimental proof-of-work hash; OpenSSL supplies SHAKE256,
KMAC256, SLH-DSA signatures, and wallet cryptography.

**Status:** local experiments. There is no peer-to-peer networking or supported
mainnet deployment. This tree has no packaged releases. The experimental hash
and protocol require independent review before production use.

## Build

Requires CMake 3.21+, Ninja, a C++20 Clang/GCC compiler with `__int128`, POSIX APIs,
and **OpenSSL 3.6.5 exactly**.

**Development host: macOS (OS X), Apple Silicon.** The local builds succeeded on
macOS 26.3 with Apple Clang 21. Linux instructions are provided but have not yet
been executed on a Linux machine.

See [build.md — macOS setup and builds](build.md) and
[LINUX.md — Linux build instructions](LINUX.md).

```sh
cmake --preset dev
cmake --build --preset dev
```

The default build produces:

| Program | Purpose |
| --- | --- |
| `e46-node` | Local chain, block validation, mining, mempool, snapshot JSON |
| `e46-wallet` | Wallet creation, fingerprints, addresses, signing, transaction display |
| `addresses_cli` | Address encoding and decoding tools |
| `transaction_cli` | Transaction serialization and validation tools |

Executables are under `build/dev/`. Optional diagnostic CLIs use the `tools`
preset. Dependencies are discovered locally; the build does not download them.

## Local use

[Local experiment guide](docs/LOCAL.md) covers wallet creation, saved fingerprints,
mining, payment submission, and read-only inspection. Store wallets and chain
data outside this repository.

```sh
E46_DATA="$HOME/E46Tessera-data/experiment-01"
./build/dev/e46-node --datadir "$E46_DATA" snapshot 10
```

An empty datadir is initialized with the frozen testnet genesis. **Height 268 is
pinned to the first-payment checkpoint.** An independently mined history cannot
cross that height with a different block. See [checkpoint policy](docs/ARCHITECTURE.md#checkpoints).
No block store or wallet is bundled in this source tree.

## Protocol at a glance

| Item | Current implementation |
| --- | --- |
| Proof of work | Refracting Light v3, 128-bit digest |
| Internal hash state | Four 128-bit lanes; 512 bits total |
| Block and transaction identifiers | 256-bit tagged SHAKE identifiers |
| Single-owner signatures | SLH-DSA-SHAKE-128s |
| Amounts | Integer base units; 100,000,000 = 1 E46 |
| Nominal block interval | 150 seconds, ASERT difficulty adjustment |
| Mining-reward maturity | 100 blocks |
| Block commitments | Separate transaction and event Merkle roots |
| Current network scope | Single-machine Phase 1 testnet |

The wallet envelope's QTL construction and the chain's block-depth QTL commitments
are distinct mechanisms. RAD events and stake-lock outputs are disabled in the
current Phase 1 node.

## Source map

```text
include/e46/       Public C++ interfaces
src/              Protocol and node implementation
src/checkpoints.cpp  Explicit testnet height/block-ID anchors
tools/            Node, wallet, and diagnostic CLI entry points
docs/             Build, local operation, and architecture notes
```

The GOLD bundles, internal work orders, Python research archive, GUI prototypes,
and historical test harnesses are maintained separately. The small public
known-answer constants embedded in `src/keys.cpp` remain part of the runtime
provider self-check; they are not wallet secrets.

## Reading and contributions

- [Research journal](https://journal.e46.dev/)
- [Visual explorer demonstration](https://explorer.e46.dev/) — public sample data
- [Contribution guide](CONTRIBUTING.md)
- [Security reporting](SECURITY.md)

Project lead: Mik3XC. Existing contributor attribution is retained in
[LICENSE](LICENSE). This source tree is licensed under MIT.
