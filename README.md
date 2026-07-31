# Confidential Voting Template for Tari Ootle

A confidential voting template for the Tari Ootle L2 platform. Voters cast unlinkable ballots using stealth-addressed vote tokens — no on-chain observer can link any vote transaction to the voter who cast it. The aggregate tally is public and trustlessly readable on-chain.

## Privacy model

This template implements a **coinjoin-style blending** design (per the project's core requirement: obscure *who sent what vote*, not the amounts):

1. **Initiator mints stealth vote tokens.** When a vote is initiated, the template mints one indivisible amount-1 vote token per eligible voter and converts them into **stealth UTXOs** — each owned by a one-time key unlinkable to the voter's real public key. The stealth outputs are built off-chain by the initiator's wallet and passed to the template as a `StealthTransferStatement`.

2. **Voters spend privately.** Each voter spends their stealth vote-token UTXO into either the `yes_vault` or the `no_vault` via `vote_yes` / `vote_no`. Because the spend is a **stealth transfer sealed with an ephemeral one-time key** (with the transaction fee paid from a separate stealth TARI UTXO), no on-chain observer can link the vote transaction to a voter identity. The `vote_*` methods deliberately never call `CallerContext::transaction_signer_public_key()` so that ephemeral sealing works.

3. **Tally is public and trustless.** Anyone can call `tally()` to read the current `(yes, no)` counts from the vault balances. Each vote is an indivisible amount-1 token, so the revealed balance of each vault equals the number of votes cast for that option.

### Double-vote prevention

Each voter receives exactly one indivisible amount-1 stealth token. A stealth UTXO can only be spent once — the engine enforces this at the consensus level. There is no way to split the token or spend it twice.

### Fee-from-stealth requirement

For a ballot to be truly unlinkable, the transaction fee must also be paid unlinkably. Each voter converts revealed TARI into a stealth TARI UTXO first, then pays the ballot transaction's fee from that stealth UTXO (with change returned to another stealth UTXO). If the fee were paid from a revealed account instead, the transaction would be linkable to the account owner.

## Template API

| Method | Access | Description |
|--------|--------|-------------|
| `new(alloc)` | — | Constructor. Creates the stealth vote resource and empty yes/no vaults. Pre-allocates the resource address so the initiator can build the mint statement. |
| `resource_address()` | allow_all | Returns the vote-token resource address. |
| `initiate_vote(voter_count, mint_statement)` | initiator-only | Mints `voter_count` revealed tokens and converts them into per-voter stealth UTXOs per the statement. Starts the vote. |
| `vote_yes(bucket)` | allow_all | Deposits a revealed vote-token bucket into the YES vault. |
| `vote_no(bucket)` | allow_all | Deposits a revealed vote-token bucket into the NO vault. |
| `tally()` | allow_all | Returns `(yes, no)` current counts. |
| `end_vote()` | initiator-only | Ends the vote, returns final tally, locks further ballots. |

> **Before publishing:** set `INITIATOR_1` / `INITIATOR_2` to the `RistrettoPublicKeyBytes` of the addresses allowed to initiate/end votes, and switch the `initiate_vote` / `end_vote` access rules from `allow_all` to `initiator_rule()`. Voter confidentiality does not depend on this (ballots are identity-free regardless), but without it anyone can start or end a vote.

## Project layout

```
templates/confidential_voting/   The template (Rust → WASM)
client/spike/                     Single-voter reference (proves the private two-input spend)
client/integration/               3-voter end-to-end test (initiator + 3 voters, tally = 2 yes, 1 no)
vendor/ootle-rs/                  Vendored ootle-rs with the two-input signing fix (see below)
```

## Build

```bash
# Compile the template to WASM
cargo build --target wasm32-unknown-unknown --release -p confidential_voting

# Build the integration test client
cargo build --bin integration
```

## Run the integration test

```bash
cargo run --bin integration
```

This runs a full 3-voter scenario on the Esmeralda testnet:
- Initiator wallet faucets, publishes the template, creates the component, and calls `initiate_vote(3, mint_statement)` to mint 3 stealth vote UTXOs (one per voter).
- Three voter wallets each faucet, convert TARI to a stealth UTXO for fees, then cast a private ballot via a two-input stealth spend (vote UTXO → `vote_yes`/`vote_no`, TARI UTXO → fee).
- `tally()` returns `(2, 1)`.

## The ootle-rs patch (for upstreaming)

The vendored `ootle-rs` at `vendor/ootle-rs/` contains a fix for a **two-stealth-input signing bug** in `src/wallet/stealth.rs` (`WalletStealthAuthorizer::create_authorizations`).

**The bug:** The engine verifies every authorization signature against the seal signature's public key. For account-sealed transactions that is the account key (K); for stealth-sealed transactions it is the seal signer's *one-time* key (P), **not** the account key. The upstream implementation always bound authorizations to K, which is invisible with a single stealth input (no authorizations needed) but produces an invalid signature as soon as a second stealth input requires an authorization signature.

**The fix** (stealth.rs:65-77): When the transaction is stealth-sealed (`must_sign_with_account_key == false`), derive the one-time stealth owner public key P via `derive_stealth_owner_public_key(seal_signer.signer(), seal_signer.public_nonce())` and bind authorization signatures to P instead of K.

This fix is what makes the private two-input ballot spend possible: the vote-token UTXO is the seal input (P_seal), and the TARI fee UTXO is an additional authorization — both signed correctly against the one-time key.

This patch is self-contained and suitable for upstreaming as a PR to [tari-ootle](https://github.com/tari-project/tari-ootle).
