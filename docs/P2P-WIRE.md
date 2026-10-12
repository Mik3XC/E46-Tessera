# E46 experimental peer transport v1

This transport is independently versioned from consensus serialization. It does
not define new consensus hashes, targets, signatures or checkpoints. Integers
in the **transport frame and HELLO** are big-endian. Existing header,
transaction and CompactSize encodings retain their established byte order.

## Frame

```text
4 bytes  ASCII E46P
4 bytes  message type, unsigned big-endian
4 bytes  payload byte length, unsigned big-endian
N bytes  payload
```

No checksum/encryption is added at this layer. Network messages carry public
chain data. Hash commitments/signatures/PoW are verified by the node; the
transport does not authenticate a peer's operator. Declared type/length bounds
are checked after the 12-byte header, before waiting for the full payload.
Unknown, out-of-sequence, malformed and oversized messages close the socket.

Both ends send HELLO immediately. Each end must validate the other's HELLO
before accepting other peer messages. A second HELLO on the same connection is
invalid. The nonce detects a connection back to the same process; it is not an
identity credential.

## Peer messages

| Type | Name | Payload |
| --- | --- | --- |
| 1 | HELLO | `u32 version=1`, `u32 network=1`, genesis ID (32), random process nonce (8), advertised tip ID (32); exactly 80 bytes |
| 2 | GETBLOCK | 1–80 concatenated 32-byte locator IDs, most recent first |
| 3 | BLOCK | One `E46NDB01` record, at most 4,100,000 bytes |
| 4 | TIP | Exactly one 32-byte block ID |
| 5 | INVENTORY | 0–1,000 concatenated pending transaction IDs |
| 6 | GETTX | Exactly one 32-byte pending transaction ID |
| 7 | TX | Expected transaction ID (32) followed by 1–4,000,000 serialized transaction bytes |
| 8 | NOTFOUND | Empty: end of block synchronization; 32-byte ID: requested transaction no longer available |

HELLO version, network and genesis must exactly match local values. The
advertised tip is informational. TIP prompts a new locator request when the ID
is unknown. It cannot cause a chain-state change by itself.

GETBLOCK finds the first supplied locator ID on the responder's **active**
chain and returns its successor. At the active tip it returns empty NOTFOUND.
No common ancestor is a protocol error. The requester's locator follows its
last received branch (when present), then uses progressively wider ancestor
steps back to genesis. This lets the requester continue receiving a competing
branch even before that branch has enough work to become its active chain.

Only one BLOCK request is outstanding per connection. A returned block must
have a known parent and pass normal consensus acceptance. Receiving the same
already-known header ID advances the cursor without applying state again.
There is no unbounded out-of-order/orphan buffer. The active branch is selected
by cumulative work, not advertised height or arrival count.

An inventory creates a bounded list of desired IDs; only one GETTX is outstanding
per connection. Transaction requests wait until that peer's block catch-up
finishes, so funding outputs can be present. TX must match the outstanding ID;
its decoded ID, UTXOs, maturity, signatures, locks and mempool conflicts are
checked before acceptance/relay. Transactions already known locally are ignored.
GETTX serves only current mempool transactions, not arbitrary chain history.

Inventory and locator polling recur every ten seconds. Requested block/tx
responses have a 30-second timeout. Manual outbound peers reconnect after five
seconds. All limits are summarized in [P2P.md](P2P.md#bounds-and-scope).

## BLOCK record payload

The transport deliberately uses the existing versioned disk record. It does
**not** claim this envelope is the consensus block byte sequence:

```text
8 bytes       E46NDB01
120 bytes     canonical header
CompactSize   transaction count
repeat:
  CompactSize transaction byte length
  bytes       canonical signed transaction
CompactSize   event count
repeat:
  u8          event type
  CompactSize ID byte length (at most 32)
  bytes       event ID
  CompactSize body byte length (at most 256)
  bytes       event body
```

The decoder rejects non-minimal CompactSize encodings, impossible counts,
truncation, and trailing bytes. The parent state determines spent-output types
needed to decode witnesses. Consensus size is calculated from consensus
serialization, independently of this envelope. Block/transaction identifiers
are calculated by the existing consensus modules.

## Private local control

Only `DATADIR/control.sock` accepts type **100** commands. Payload is one UTF-8
CLI argument per newline, with no embedded NUL or newline in an argument and at
most eight arguments. Exactly one request is processed per connection. Reply
**101** contains ordinary command output; **102** contains an error message.
The response is followed by connection closure. These types are rejected on TCP.

Socket mode is 0600. The node holds its datadir writer lock before creating or
replacing its stale control socket. Control replies/requests have a 16 MiB
frame bound. Administrative commands include `status`, `stop`, `stop-mining`,
`import`, asynchronous `mine`, and the existing CLI reads/submission. `rebuild`
requires the daemon to stop and acquire the exclusive datadir lock separately.

This is a first local protocol revision. Compatibility changes to this document
or the implementation should be reviewed and versioned before peer deployments.
