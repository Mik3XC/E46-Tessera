# Local P2P exercise — 2026-10-10

## Environment and result

**Passed on macOS 26.3 / Apple Silicon**, Apple Clang 21, OpenSSL 3.6.5.
Both the development build and ASan/UBSan build compiled successfully with the
project's `-Wall -Wextra -Werror` settings. The full historical integration
exercise passed in both configurations. The development run additionally mined
and relayed a fresh proof-of-work block. No sanitizer diagnostic appeared in
the sanitized exercise logs.

All node state was isolated under `~/Library/Caches/E46Tessera/p2p-*`.
The original historical datadir was read as a fixture source; it was not changed.
No wallet, password or private key was loaded. The payment fixture was an
already-signed public transaction. No source publication or release was made.

## Demonstrated behavior

- A persistent node loaded the historical chain through height 267. A second
  node started at genesis, fetched and validated the missing blocks, and reached
  exactly the same tip. Snapshot reads used the running daemon and reported P2P.
- A second writer and a rebuild against an active daemon's datadir were refused.
- Wrong protocol version, network number and genesis ID were rejected.
- Oversized frame declarations and TCP attempts to issue local control commands
  were rejected.
- The default eight-peer cap was enforced while local control remained usable.
  A peer that never completed HELLO was disconnected at its handshake deadline.
- A corrupt block received over TCP was rejected without moving the tip.
  A height-268 checkpoint mismatch and invalid PoW beyond that checkpoint were
  also rejected.
- A modified transaction signature received over TCP was rejected.
- The valid first payment was submitted to node A, persisted, announced, fetched
  and accepted into node B's mempool.
- Another fresh peer downloaded the funding chain before validating the pending
  payment; catch-up did not fail due to temporarily missing funding outputs.
- Node B was killed abruptly and restarted. It recovered the validated chain
  and the pending signed payment from disk, including stale-socket recovery.
- Importing the already-mined height-268 record on A caused B to fetch and
  validate it. Both mempools removed the confirmed payment; both recipient
  balances were exactly **100,000,000 base units (1 E46)**.
- Height 269 propagated, and resubmitting the spent payment was rejected.
- Background mining left local status queries responsive and could be canceled.
- Full local replay rebuilt the identical tip. A missing ancestor and a damaged
  record caused rebuild failure without deleting the damaged evidence.
- A fresh datadir reconstructed the complete height-269 chain entirely from its
  peer, without copying the peer's block files.
- A regular file named `control.sock` was rejected and preserved rather than
  mistaken for a stale Unix socket (separate fixture-free sanitizer run).

## Fresh mining and relay

The development daemon then mined **height 270 in the disposable exercise
chain**, using the unchanged consensus target and one background worker.
The connected second daemon validated and stored the identical block:

```text
height: 270
block ID: e8feb636c89a8b521c504aa79c807b3efcad3c6ece3ef7d2c7982a137ce12c96
nonce: 27408634
```

This result was produced by `--mine-real`, not by importing that block. It did
not advance the original historical datadir, and no new checkpoint was added.
The existing height-268 checkpoint remains unchanged. All exercise child
processes stopped at the end.

## Coverage limits

These checks demonstrate the listed local behavior, not a security audit or
Internet load test. Linux, Raspberry Pi and Orange Pi execution, NAT traversal,
long-lived public hosting, deliberate competing-work forks/reorgs, QTL relay,
maximum-size valid blocks and power-loss durability remain separate exercises.
No consensus target was weakened and no signature/checkpoint check was bypassed.

The reproduction commands and operational limits are in [P2P.md](P2P.md).
