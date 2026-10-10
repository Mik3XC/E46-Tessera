# Local experiments

Run the examples from the repository root. The node is a one-shot CLI: each
invocation loads the local block store, performs a command, and exits. `mine`
runs until the requested count is complete or you interrupt it. There is no
background P2P daemon.

## 1. Separate source, wallets, and chain data

```sh
E46_NODE="$PWD/build/dev/e46-node"
E46_WALLET="$PWD/build/dev/e46-wallet"
E46_DATA="$HOME/E46Tessera-data/experiment-01"
E46_WALLET_DIR="$HOME/E46Tessera-wallets"
mkdir -p "$E46_WALLET_DIR"
chmod 700 "$E46_WALLET_DIR"
```

Use a fresh experiment directory, or an explicit path to a compatible existing
store. The first node invocation creates missing datadir directories and the
frozen genesis. Never run two mining/writing processes against the same store.

This code retains the testnet checkpoint at height 268. Fresh experiments can
mine below it; to continue through it, use the matching historical chain. An
alternate checkpoint policy would define a different experiment and must be
reviewed explicitly. There is no checkpoint bypass flag.

## 2. Create a wallet and retain its fingerprint

```sh
"$E46_WALLET" new "$E46_WALLET_DIR/miner.wallet"
```

The CLI prompts for a password twice and prints the wallet's fingerprint. Keep
that fingerprint separately, along with your wallet backups. It is the reference
used to detect a changed wallet envelope. Passwords are entered at the prompt,
not in the command line. The file is written exactly where you specify.

Set the following to the fingerprint printed by your own wallet creation:

```sh
E46_FP='REPLACE_WITH_YOUR_SAVED_FINGERPRINT'
"$E46_WALLET" address 0 --wallet "$E46_WALLET_DIR/miner.wallet" --fingerprint "$E46_FP"
```

Save the returned `te46...` address as `E46_ADDRESS` for subsequent commands.
No private wallet, seed, password, or personal fingerprint is included here.

## 3. Inspect and mine

```sh
E46_ADDRESS='REPLACE_WITH_YOUR_TESTNET_ADDRESS'
"$E46_NODE" --datadir "$E46_DATA" snapshot 10
"$E46_NODE" --datadir "$E46_DATA" mine 1 "$E46_ADDRESS"
"$E46_NODE" --datadir "$E46_DATA" balance "$E46_ADDRESS"
```

`balance` returns integer base units and currently includes immature mining
rewards. Divide by 100,000,000 for E46. An output mined at height H is eligible
for a spending block at H + 100. Ordinary change/payment outputs do not acquire
that coinbase maturity delay.

## 4. Build a single-owner payment

The wallet currently builds a one-input payment from an explicitly identified
type-0 output. It checks ownership and creates change when needed. It does not
automatically select UTXOs.

The spent-output descriptor has seven colon-separated fields:

```text
previous_txid:output_index:value_base_units:output_type:payload_hex:is_coinbase:creation_height
```

Use the actual output from the chain. `is_coinbase` is 1 or 0; output type is a
decimal integer. `KEY_INDEX` identifies the wallet address owning that output.
`HEIGHT` is the intended spending block height, not the creation height.

Command syntax (uppercase arguments below are placeholders):

```text
e46-wallet build WALLET FP SPENT_DESC KEY_INDEX RECIPIENT AMOUNT FEE HEIGHT
e46-wallet show TX_HEX SPENT_DESC
```

`build` prompts for the wallet password and prints signed transaction hex.
Amounts and fees use integer base units. Save that hex outside the repository.

## 5. Submit, preview, mine, confirm

```sh
E46_TX_FILE="$HOME/E46Tessera-data/payment.tx.hex"
E46_RAW=$(cat "$E46_TX_FILE")
"$E46_NODE" --datadir "$E46_DATA" submit "$E46_RAW"
"$E46_NODE" --datadir "$E46_DATA" mempool
"$E46_NODE" --datadir "$E46_DATA" template "$E46_ADDRESS"
"$E46_NODE" --datadir "$E46_DATA" mine 1 "$E46_ADDRESS"
```

Stop an existing miner before submitting. `ACCEPTED` means stored in the local
mempool, not broadcast or confirmed. The template is labeled `NOT_MINED`. Check
the transaction ID in that template before mining. Once mining returns a block
height, inspect `getblock HEIGHT` for the transaction ID. `gettx TXID` also finds
pending transactions, so it alone does not establish confirmation.

An already-confirmed payment has consumed its input. Resubmitting those same
bytes can report an unknown/already-spent output; first check the containing
block before creating or signing another payment.

## Explorer integration

`snapshot 10` emits the latest ten validated active-chain blocks as JSON,
including decoded transactions, input/output fields, witness metadata, signature
hashes, and full serialized bytes. Coinbase transactions have no signature hash.
Amounts and lock times use decimal strings to preserve exact integers in browser
consumers. Consumers should handle large payloads and display long hex in a
collapsible, scrollable panel.

An external local web bridge can invoke that read-only command and serve its
result. This repository does not start an HTTP server. Configure an existing
bridge to use this tree's `build/dev/e46-node` and the intended datadir.
