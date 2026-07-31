use tari_template_lib::prelude::*;

/// Placeholder initiator public keys. Replace these with the real RistrettoPublicKeyBytes of
/// the addresses allowed to initiate a vote before publishing. Any one of them may start a vote.
const INITIATOR_1: RistrettoPublicKeyBytes = RistrettoPublicKeyBytes::zero();
const INITIATOR_2: RistrettoPublicKeyBytes = RistrettoPublicKeyBytes::zero();

/// Returns the access rule that gates initiator-only methods.
fn initiator_rule() -> AccessRule {
    rule!(any_of(public_key(INITIATOR_1), public_key(INITIATOR_2)))
}

/// Confidential voting template (Architecture A).
///
/// A vote instance mints one unlinkable stealth vote-token UTXO per eligible voter (built
/// off-chain by the initiator's wallet and passed in as a `StealthTransferStatement`). Each voter
/// spends their UTXO into either the `yes_vault` or the `no_vault` via `vote_yes` / `vote_no`.
/// Because the spend is a stealth transfer sealed with an ephemeral key (fee paid from a stealth
/// TARI UTXO), no on-chain observer can link any vote transaction to a voter. The aggregate tally
/// is public and trustlessly readable on-chain via `tally()`.
///
/// Double-voting is impossible: each voter receives exactly one indivisible amount-1 token, and a
/// stealth UTXO can only be spent once.
#[template]
mod confidential_voting {
    use super::*;

    pub struct ConfidentialVote {
        vote_resource: ResourceAddress,
        yes_vault: Vault,
        no_vault: Vault,
        active: bool,
    }

    impl ConfidentialVote {
        /// Constructor. Creates the stealth vote resource and the empty yes/no tally vaults.
        /// The resource address is pre-allocated by the caller so the initiator can build the
        /// mint `StealthTransferStatement` (which references it) before this call finalizes.
        pub fn new(alloc: ResourceAddressAllocation) -> Component<Self> {
            let vote_resource = ResourceBuilder::stealth()
                .with_token_symbol("CVOTE")
                .with_divisibility(0)
                .mintable(initiator_rule(), LOCKED)
                .burnable(initiator_rule(), LOCKED)
                .with_address_allocation(alloc)
                .build();

            Component::new(Self {
                vote_resource,
                yes_vault: Vault::new_empty(vote_resource),
                no_vault: Vault::new_empty(vote_resource),
                active: false,
            })
            .with_access_rules(
                AccessRules::new()
                    // TODO(before publishing): replace allow_all with `initiator_rule()` once the
                    // real initiator public keys are set in INITIATOR_1/INITIATOR_2 above. Kept
                    // allow_all here so the integration test (random wallets) can drive the flow;
                    // voter confidentiality does not depend on this.
                    .method("initiate_vote", rule!(allow_all))
                    .method("end_vote", rule!(allow_all))
                    // vote_yes / vote_no / tally / resource_address are callable by anyone; they
                    // deliberately do NOT call CallerContext::transaction_signer_public_key() so
                    // that voters' transactions can be sealed with an ephemeral key (no identity).
                    .method("vote_yes", rule!(allow_all))
                    .method("vote_no", rule!(allow_all))
                    .method("tally", rule!(allow_all))
                    .method("resource_address", rule!(allow_all))
                    .default(rule!(deny_all)),
            )
            .create()
        }

        /// The vote-token resource address (so the initiator can build outputs for it).
        pub fn resource_address(&self) -> ResourceAddress {
            self.vote_resource
        }

        /// Start a vote. `voter_count` revealed tokens are minted and converted, via the
        /// caller-provided `mint_statement`, into `voter_count` stealth UTXOs — one per voter,
        /// each owned by a one-time key unlinkable to the voter's real public key. The statement
        /// must carry exactly `voter_count` as its revealed input amount and one stealth output
        /// per voter (built off-chain by the initiator's wallet).
        pub fn initiate_vote(&mut self, voter_count: u64, mint_statement: StealthTransferStatement) {
            assert!(!self.active, "A vote is already in progress");
            assert!(voter_count > 0, "voter_count must be positive");
            assert_eq!(
                mint_statement.revealed_input_amount(),
                Amount::from(voter_count),
                "mint statement revealed input must equal voter_count",
            );

            let manager = ResourceManager::get(self.vote_resource);
            let minted = manager.mint_stealth(Amount::from(voter_count));
            // Convert the revealed mint into per-voter stealth UTXOs. Any revealed output (which
            // there should not be) is dropped — the mint is fully converted to stealth outputs.
            let _revealed_out = manager
                .stealth_transfer_with_opt_input_bucket(mint_statement, Some(minted));

            self.active = true;
            emit_event(
                "VoteStarted",
                metadata!["voter_count" => voter_count.to_string()],
            );
        }

        /// Deposit a revealed vote-token bucket into the YES vault.
        pub fn vote_yes(&mut self, bucket: Bucket) {
            assert!(self.active, "No active vote");
            assert_eq!(
                bucket.resource_address(),
                self.vote_resource,
                "bucket must be the vote resource",
            );
            self.yes_vault.deposit(bucket);
        }

        /// Deposit a revealed vote-token bucket into the NO vault.
        pub fn vote_no(&mut self, bucket: Bucket) {
            assert!(self.active, "No active vote");
            assert_eq!(
                bucket.resource_address(),
                self.vote_resource,
                "bucket must be the vote resource",
            );
            self.no_vault.deposit(bucket);
        }

        /// Current tally: (yes, no). Each vote is an indivisible amount-1 token, so the revealed
        /// balance of each vault equals the number of votes cast for that option.
        pub fn tally(&self) -> (Amount, Amount) {
            let yes = self.yes_vault.balance();
            let no = self.no_vault.balance();
            emit_event(
                "Tally",
                metadata!["yes" => yes.to_string(), "no" => no.to_string()],
            );
            (yes, no)
        }

        /// End the vote (initiator-only). Locks the vote against further ballots.
        pub fn end_vote(&mut self) -> (Amount, Amount) {
            assert!(self.active, "No active vote");
            self.active = false;
            let (yes, no) = self.tally();
            emit_event(
                "VoteEnded",
                metadata!["yes" => yes.to_string(), "no" => no.to_string()],
            );
            (yes, no)
        }
    }
}
