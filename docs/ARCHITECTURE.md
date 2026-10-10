# Architecture and scope

## Components

| Files under `src/` | Responsibility |
| --- | --- |
| `rl.cpp`, `rl_detail.hpp` | Refracting Light arithmetic and fold |
| `shake.cpp`, `keys.cpp` | OpenSSL SHAKE/KMAC wrappers and SLH-DSA keys/signatures |
| `bech32m.cpp`, `addresses.cpp` | Address and identifier encoding |
| `transaction.cpp` | Typed outputs, witnesses, serialization, signing hashes and validation |
| `merkle.cpp` | Tagged commitment trees and events |
| `header.cpp`, `emission.cpp`, `genesis.cpp` | Headers, difficulty, reward calculations and genesis |
| `rad.cpp`, `block_qtl.cpp` | Puzzle and block-QTL support; phase policy is enforced by the node |
| `qtl_v2.cpp` | Wallet-envelope cryptographic building blocks |
| `node.cpp` | Block store, branch state, UTXOs, mempool, validation and local mining |
| `checkpoints.cpp` | Explicit testnet block anchors |

`tools/e46_node.cpp` handles the local CLI and explorer snapshot output.
`tools/e46_wallet.cpp` handles wallet envelopes and signing. Headers live under
`include/e46/`; public interfaces retain the `e46` namespace.

## Checkpoints

The current table in `src/checkpoints.cpp` contains:

| Height | Block ID |
| --- | --- |
| 268 | `4e6bd53958345c17ae9a3f338767e69b7da8a9c8ac361b7ba591eb26506958de` |

This records the first ordinary payment milestone. Validation rejects a
different block ID at that height both during stored-block replay and new block
acceptance. Every accepted descendant must therefore pass through the matching
height-268 block. Normal PoW, transaction and commitment checks still run.

This is an explicit early milestone anchor selected by the project owner. It
predates the proposed routine policy of selecting release checkpoints at least
1,000 blocks deep. There are no automatic rolling checkpoints. Checkpoints
represent trust in the chosen history and publisher; they do not add hash work.

Changing the checkpoint table affects compatible histories. A new independently
mined chain will almost certainly produce a different block at height 268 and
cannot continue through this anchor. No historical block data is bundled here.

## Persistence

Blocks are stored under `DATADIR/blocks/`. Accepted signed transactions are
published to `DATADIR/mempool/<txid>.tx` before acceptance is reported. Startup
revalidates the cache against the active chain; invalid entries are ignored.
The CLI holds `node-write.lock` during submit/mining commands. This is a local
writer lock, not a peer protocol or a transactional multi-process database.

## Boundaries

This is a source-only extraction for local development. GOLD files, independent
Python reference implementations, historical test harnesses, research reports,
Qt UI prototypes and web frontends remain in their separate working trees.

The local node has no peer discovery, synchronization, remote RPC, or transaction
broadcasting. Existing cryptographic primitives and passing development checks
do not establish the security of the custom proof-of-work construction or the
complete protocol. No independent audit is claimed.
