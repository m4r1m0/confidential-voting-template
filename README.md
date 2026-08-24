# Confidential Voting Template (Yes/No) for Tari Ootle

> ## ⚠️ Minify the WASM before you publish
>
> ```bash
> cargo build --target wasm32-unknown-unknown --release -p confidential_voting
> wasm-opt -Oz --enable-bulk-memory \
>     target/wasm32-unknown-unknown/release/confidential_voting.wasm \
>     -o target/wasm32-unknown-unknown/release/confidential_voting.min.wasm
> ```
>
> Publish `confidential_voting.min.wasm` (~198 KB), never the raw `.wasm` (~231 KB). Publish fees
> scale with WASM size, and every validator stores the template forever — an unminified
> artifact costs roughly 15% more for the life of the chain.

A confidential yes/no voting template for the Tari Ootle L2 platform. Voters cast unlinkable ballots using stealth-addressed vote tokens — no on-chain observer can link any vote transaction to the voter who cast it. The aggregate tally is public and trustlessly readable on-chain.

This template shares its privacy model and hardening with the sibling ranked-choice template ([confidential-rcv-template](https://github.com/m4r1m0/confidential-rcv-template)) — instant-runoff / multi-winner elections live there.

## Privacy model

This template implements a **coinjoin-style blending** design (per the project's core requirement: obscure *who sent what vote*, not the amounts):

1. **The initiator mints stealth vote tokens.** Creating a vote mints one indivisible amount-1 vote token per eligible voter and converts them into **stealth UTXOs** — each owned by a one-time key unlinkable to the voter's real public key. The stealth outputs are built off-chain by the initiator's wallet and passed to the template as a `StealthTransferStatement`. The supply is permanently capped at `voter_count` (see [Vote supply cap](#vote-supply-cap-no-extra-votes)).

2. **Voters spend privately.** Each voter spends their stealth vote-token UTXO into either the `yes_vault` or the `no_vault` via `vote_yes` / `vote_no`. Because the spend is a **stealth transfer sealed with an ephemeral one-time key** (with the transaction fee paid from a separate stealth TARI UTXO), no on-chain observer can link the vote transaction to a voter identity. The `vote_*` methods deliberately never call `CallerContext::transaction_signer_public_key()` so that ephemeral sealing works.

3. **Tally is public, on-chain, and trustless.** Anyone can call `tally()` to read the current `(yes, no)` counts from the vault balances. Each vote is an indivisible amount-1 token, so the revealed balance of each vault equals the number of votes cast for that option.

### What is private vs. public

| Private (hidden) | Public (on-chain) |
|---|---|
| Voter identity (who cast which vote) | Vote direction (each transaction reveals yes vs no) |
| Which UTXO belonged to which voter | Number of votes cast per side |
| | The running tally |

This is consistent with the sibling template's model: voter *anonymity* is protected by stealth-address unlinkability; the *aggregate* outcome is deliberately visible so the tally needs no trusted authority.

### Double-vote prevention

Each voter receives exactly one indivisible amount-1 stealth token; the mint-statement invariants (below) force every vote to be exactly one token at construction. A stealth UTXO can only be spent once — the engine enforces this at the consensus level — so a 1-token vote cannot be split or cast twice.

### Vote supply cap (no extra votes)

The vote supply is permanently capped at the initial `voter_count`; nobody — including the initiator — can mint additional votes after creation. The vote resource's mint rule requires a proof of a **one-of NFT badge** ("CVOTE-MINT") that is created and sealed inside the component during `new()`:

- The badge's own mint/burn/recall rules are `deny_all` with locked updaters, so no second badge can ever exist and the sole copy can never be destroyed or recalled.
- The badge lives in a component vault that no template method exposes, so its proof can never be re-obtained. (Transactions cannot reach a vault directly: the transaction instruction set has no instruction that targets a vault address — see the `Instruction` enum in `tari_ootle_transaction` — so vaults are only reachable from within their owning component's method code.)
- The vote resource is **ownerless** (`OwnerRule::None`), closing the resource-owner authorization path that would otherwise bypass the mint rule.
- The mint rule's updater is `LOCKED`, so the rule itself can never be changed.

The cap is verifiable by anyone: `voter_count()` returns the number of votes minted, and the vote resource's total supply never exceeds it. Votes can never be burned (`burnable` is `deny_all`), so total supply is immutable.

### Mint-statement invariants

`new()` verifies three things about the mint statement it receives: its revealed input total equals `voter_count`, it creates exactly `voter_count` stealth outputs — one per voter — and every output promises a minimum value of at least one token. Each output's promise is public, and the engine's range-proof verification binds the output's committed value to be at least its promise; with `voter_count` outputs of at least one token each that sum to exactly `voter_count`, every vote is forced to be exactly one token at construction. Wrong-valued shapes like `[2,0]` (a 2-token vote plus a worthless 0-token output) are therefore unconstructible: a 0-value output can only ever be proven with a promise of 0, which the constructor rejects. The cast-time `amount == 1` guard remains as defense in depth. The mint statement is a public argument of the initiating transaction, so scrutineers can audit exactly what was minted and to which addresses.

One limitation cannot be fixed in the template: nothing on-chain can verify that the minted outputs are distributed to *distinct* voters (two amount-1 votes could be addressed to the same person, leaving another voter with none). Voter identity and vote assignment are off-chain; the initiating transaction's public mint statement is the audit point for that.

### Fee-from-stealth requirement (MUST)

For a ballot to be truly unlinkable, the transaction fee must also be paid unlinkably. **Every ballot transaction MUST pay its fee from a stealth TARI UTXO.** Each voter converts revealed TARI into a stealth TARI UTXO first, then pays the ballot transaction's fee from that stealth UTXO (with change returned to another stealth UTXO).

Paying the fee from a revealed source breaks anonymity completely: the fee input links the transaction to the account owner, and because the ballot transaction itself reveals the vote direction (yes vault vs no vault), that link exposes not only *who voted* but *how they voted*. A revealed fee input effectively defeats the entire stealth mechanism.

The reference client in `client/integration` implements the canonical pattern in `cast_private_ballot`: a two-input stealth spend that uses the vote-token UTXO as the seal input and a stealth TARI UTXO as the fee input, both bound to the same ephemeral one-time key. Wallet code that builds ballot transactions should follow that pattern exactly — the template cannot enforce it (it never sees fee inputs), so this requirement is a client-side contract.

Fees paid from a bucket (`pay_fee_from_bucket`) are **non-refundable**: the engine takes the revealed fee bucket in full and burns any excess to the fee pool — there is no refund destination that could link a ballot back to a revealed account. The reference client therefore reveals a flat `VOTE_FEE` per ballot that comfortably exceeds the actual fee; the overpay is deliberately uniform so every ballot transaction reveals the same fee.

### Election expiration

Elections have an `expires_at_epoch` deadline set at creation. After the deadline, no more ballots may be cast (`vote_yes` / `vote_no` check `Consensus::current_epoch()`). This prevents an election from being held up indefinitely by voters who never spend their stealth vote tokens.

After expiration, `end_vote_expired()` finalizes the tally with whatever ballots were actually cast. It is callable by anyone, so the election cannot be held up by an initiator who never returns; the initiator can also use it.

## Template API

| Method | Access | Description |
|---|---|---|
| `new(alloc, voter_count, expires_at_epoch, mint_statement)` | — | Constructor. Creates the stealth vote resource, mints per-voter stealth vote UTXOs, seals the mint badge (permanently capping the supply at `voter_count`), and starts the vote — all in one transaction. The caller of `new` is the **initiator**. |
| `resource_address()` | allow_all | Returns the vote-token resource address. |
| `voter_count()` | allow_all | Returns the number of eligible voters (the vote supply, which can never grow). |
| `vote_yes(bucket)` | allow_all | Deposits one token into the YES vault. Identity-free. Rejects after expiration. |
| `vote_no(bucket)` | allow_all | Deposits one token into the NO vault. Identity-free. Rejects after expiration. |
| `tally()` | allow_all | Returns the current `(yes, no)` counts. Read-only. |
| `end_vote()` | initiator-only | Ends the vote, returns the final `(yes, no)` tally, locks further ballots. |
| `end_vote_expired()` | anyone (after the deadline) | Finalizes an expired election with the final tally (even if not all ballots cast). |

The initiator is whoever called `new()` — no keys need to be edited before publishing. Only the initiator can end a live vote; anyone can finalize it once the deadline has passed, so an absent initiator cannot hold up finalization. Voter confidentiality does not depend on this gate (ballots are identity-free regardless); it exists so only the vote's creator can close it early.

## Project layout

```
templates/confidential_voting/   The template (Rust → WASM, pure cdylib)
  src/lib.rs                     Template
  tests/test.rs                  Adversarial + end-to-end in-process tests (11)
client/integration/             3-voter end-to-end test on the Esmeralda testnet (for primary testing see tests/test.rs, which covers the same scenario in-process)
```

## Build

```bash
# Compile the template to WASM
cargo build --target wasm32-unknown-unknown --release -p confidential_voting

# Run the tests
cargo test -p confidential_voting

# Build the integration test client
cargo build -p integration
```

### Publishing

Minify the release build with [wasm-opt](https://github.com/WebAssembly/binaryen) before
publishing (see the notice at the top of this README):

```bash
wasm-opt -Oz --enable-bulk-memory \
    target/wasm32-unknown-unknown/release/confidential_voting.wasm \
    -o target/wasm32-unknown-unknown/release/confidential_voting.min.wasm
```

Publish `target/wasm32-unknown-unknown/release/confidential_voting.min.wasm`. The publish fee
scales with WASM size — unused fee is refunded (see `PUBLISH_FEE` in
`client/integration/src/main.rs`) — and a smaller artifact also downloads and instantiates
faster for voters.

## Run the integration test

First minify the template as shown above — the client publishes the minified artifact
(`target/wasm32-unknown-unknown/release/confidential_voting.min.wasm`).

```bash
cargo run -p integration
```

This runs a full 3-voter yes/no scenario on the Esmeralda testnet:

- Initiator wallet faucets, publishes the template, creates the component with `new(voter_count = 3, expires_at_epoch, mint_statement)`, minting 3 stealth vote UTXOs (one per voter).
- Three voter wallets each faucet, convert TARI to a stealth UTXO for fees, then cast a private ballot via a two-input stealth spend (vote UTXO → `vote_yes`/`vote_no`, TARI UTXO → fee).
- `end_vote()` returns the final tally: **(yes = 2, no = 1)**.

## Stealth auth signatures commit to the sealing one-time key

The private two-input ballot spend relies on **stealth authorization signatures committing to the seal signer's one-time key (P)**, not the account key (K): the engine verifies every authorization against `seal_signature().public_key()`, which for a stealth-sealed transaction is the one-time key derived from the seal input's sender nonce. Binding authorizations to K instead produces an "Invalid transaction signature" as soon as a second stealth input needs an authorization — invisible with a single stealth input (no authorizations are produced), which is why it went unnoticed upstream.

An earlier fix for this, [tari-project/tari-ootle#2390](https://github.com/tari-project/tari-ootle/pull/2390), was superseded by a fuller rework ([#2403](https://github.com/tari-project/tari-ootle/pull/2403), released in `ootle-rs` 0.18.0): signature requirements now resolve the seal source once (`SignatureRequirements::stealth_seal_with(seal_signer, authorizers)` — the ballot UTXO seals, the TARI fee UTXO authorizes), the seal key is derivable before signing, and `TransactionRequest::build()` asks the authorizer for the authorizations its inputs require before sealing. No patching or vendoring is needed — the crates.io dependencies carry the fix.
