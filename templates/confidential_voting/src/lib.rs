use tari_template_lib::prelude::*;

///
/// A confidential yes/no voting template for the Tari Ootle L2 platform. A vote instance mints
/// one unlinkable stealth vote-token UTXO per eligible voter (built off-chain by the initiator's
/// wallet and passed in as a `StealthTransferStatement`). Each voter spends their UTXO into
/// either the `yes_vault` or the `no_vault` via `vote_yes` / `vote_no`. Because the spend is a
/// stealth transfer sealed with an ephemeral key (fee paid from a stealth TARI UTXO), no
/// on-chain observer can link any vote transaction to a voter. The aggregate tally is public
/// and trustlessly readable on-chain via `tally()`.
///
/// This template shares its privacy model with the sibling ranked-choice template
/// (`confidential-rcv-template`): obscure *who*, not *what*.
///
/// Double-voting is impossible: the mint statement's per-output minimum-value promises (asserted
/// in `new` and bound by the engine's range proof) pin every vote token to exactly one token at
/// construction, and a stealth UTXO can only be spent once.
///
/// The vote supply is also permanently capped: minting vote tokens requires a proof of a one-of
/// NFT badge that is sealed inside the component at construction. After creation, nobody —
/// including the initiator — can mint additional votes. The vote resource is ownerless
/// (`OwnerRule::None`), so the resource-owner authorization path cannot be used to bypass the
/// mint rule either.
#[template]
pub mod confidential_voting {
    use super::*;

    pub struct ConfidentialVote {
        vote_resource: ResourceAddress,
        /// Resource holding the single one-of mint badge that authorizes minting vote tokens.
        mint_badge_resource: ResourceAddress,
        /// Sealed vault holding the sole mint badge. The badge's mint/burn/recall rules are
        /// `deny_all` with locked updaters and no template method exposes this vault, so the
        /// vote supply is permanently capped at `voter_count`.
        mint_badge_vault: Vault,
        /// Tally vaults. Each vote is an indivisible amount-1 token, so each vault's revealed
        /// balance equals the number of votes cast for that option. Their sum equals the number
        /// of ballots cast.
        yes_vault: Vault,
        no_vault: Vault,
        /// The number of eligible voters: the vote supply minted at construction. The supply can
        /// never grow after construction (see `mint_badge_vault`).
        voter_count: u64,
        /// The epoch after which no more ballots may be cast. Prevents elections from being held
        /// up indefinitely by voters who never spend their stealth vote tokens.
        expires_at_epoch: u64,
        active: bool,
    }

    impl ConfidentialVote {
        /// Constructor — creates the component, the stealth vote resource, mints the per-voter
        /// stealth UTXOs, and starts the vote in a single transaction.
        ///
        /// # Parameters
        ///
        /// - `alloc`: Pre-allocated resource address. The caller allocates this before the
        ///   transaction so the `mint_statement` can reference it. The resource is created inside
        ///   this call with `with_address_allocation(alloc)`.
        /// - `voter_count`: Number of eligible voters. One stealth vote UTXO is minted per voter.
        /// - `expires_at_epoch`: Deadline after which no more ballots may be cast. Prevents
        ///   elections from being held up indefinitely by voters who never spend their stealth
        ///   vote tokens. After expiration, `end_vote_expired()` finalizes the tally with
        ///   whatever ballots were actually cast.
        /// - `mint_statement`: Built off-chain by the initiator's wallet. Must carry exactly
        ///   `voter_count` as its revealed input amount and exactly `voter_count` stealth
        ///   outputs, one per voter — both asserted below — and each output must promise a
        ///   minimum value of at least one token (also asserted below). Because the engine's
        ///   range proof binds every committed output value to be at least its promise, the
        ///   total, output-count, and per-output promise checks together force every vote to be
        ///   exactly one token at construction; the cast-time `amount == 1` guard remains as
        ///   defense in depth.
        ///
        /// The caller of `new` is the initiator: before the deadline only they may end the vote;
        /// after the deadline anyone may finalize it. No template fields need to be edited before
        /// publishing — the initiator's key is captured from the transaction here, and the vote
        /// supply is permanently capped at `voter_count`: the mint rule of the vote resource
        /// requires a proof of a one-of badge that is sealed in the component by this call, so no
        /// further votes can ever be minted.
        pub fn new(
            alloc: ResourceAddressAllocation,
            voter_count: u64,
            expires_at_epoch: u64,
            mint_statement: StealthTransferStatement,
        ) -> Component<Self> {
            assert!(voter_count > 0, "voter_count must be positive");
            assert_eq!(
                mint_statement.revealed_input_amount(),
                Amount::from(voter_count),
                "mint statement revealed input must equal voter_count",
            );
            // One stealth output per voter (see the `mint_statement` doc comment above).
            assert_eq!(
                mint_statement.stealth_outputs().len() as u64,
                voter_count,
                "mint statement must create one stealth output per voter",
            );
            // Every output must promise a minimum value of one token. Each output's promise is
            // public and the engine's range-proof verification binds the output's committed value
            // to be at least its promise. So with `voter_count` outputs of at least one token each
            // that sum to exactly `voter_count`, no output can hold zero or more than one token:
            // every vote is exactly one token at construction. The cast-time `amount == 1`
            // guard remains as defense in depth.
            for output in mint_statement.stealth_outputs() {
                assert!(
                    output.output.minimum_value_promise >= 1,
                    "each vote output must promise a minimum value of 1",
                );
            }

            // The caller of `new` is the initiator: their key gates ending the vote before the
            // deadline. Capturing the key here instead of hard-coding placeholders means nothing
            // needs to be edited before publishing.
            let initiator = CallerContext::transaction_signer_public_key();

            // The vote resource's mint rule requires a proof of a one-of NFT badge that is sealed
            // in `mint_badge_vault` when the component is created. The badge authorizes the vote
            // mint inside this constructor only. The badge's mint/burn/recall rules are deny_all
            // with locked updaters (no second badge can ever exist, and the sole copy can never
            // be destroyed or recalled); its withdraw rule must stay allow_all because creating
            // the constructor's proof is authorized under it (the engine checks
            // `BucketAction::CreateProof` against the Withdraw access rule) — but the rule is
            // inert after construction: the transaction instruction set has no instruction that
            // targets a vault address (see the `Instruction` enum in `tari_ootle_transaction`),
            // so vaults are reachable only from within their owning component's method code, and
            // no template method ever exposes `mint_badge_vault`. The vote resource is
            // ownerless, so the vote supply is permanently capped at `voter_count`.
            let badge_bucket = ResourceBuilder::non_fungible()
                .with_token_symbol("CVOTE-MINT")
                .with_owner_rule(OwnerRule::None)
                .mintable(rule!(deny_all), LOCKED)
                .burnable(rule!(deny_all), LOCKED)
                .recallable(rule!(deny_all), LOCKED)
                .withdrawable(rule!(allow_all), LOCKED)
                .update_non_fungible_data(rule!(deny_all), LOCKED)
                .initial_supply_with_data(vec![(NonFungibleId::from_u64(0), (&metadata![], &()))]);
            let mint_badge_resource = badge_bucket.resource_address();

            let vote_resource = ResourceBuilder::stealth()
                .with_token_symbol("CVOTE")
                .with_divisibility(0)
                .with_owner_rule(OwnerRule::None)
                .mintable(rule!(resource(mint_badge_resource)), LOCKED)
                .burnable(rule!(deny_all), LOCKED)
                .with_address_allocation(alloc)
                .build();

            // Mint voter_count revealed tokens and convert them into per-voter stealth UTXOs via
            // the caller-provided mint statement. Any revealed output (which there should not
            // be) is dropped — the mint is fully converted to stealth outputs. The proof is
            // dropped (releasing its lock on the badge) so the badge can be sealed in the
            // component.
            let mint_proof = badge_bucket.create_proof();
            let manager = ResourceManager::get(vote_resource);
            let minted = manager.mint_stealth(Amount::from(voter_count));
            let _revealed_out =
                manager.stealth_transfer_with_opt_input_bucket(mint_statement, Some(minted));
            mint_proof.drop();

            Component::new(Self {
                vote_resource,
                mint_badge_resource,
                mint_badge_vault: Vault::from_bucket(badge_bucket),
                yes_vault: Vault::new_empty(vote_resource),
                no_vault: Vault::new_empty(vote_resource),
                voter_count,
                expires_at_epoch,
                active: true,
            })
            .with_access_rules(
                AccessRules::new()
                    // Initiator-only: the caller of `new` is the initiator, and their key (see
                    // above) is the only one that may end a live vote. After the deadline anyone
                    // may finalize via `end_vote_expired`, so an absent initiator cannot hold up
                    // finalization. Voter confidentiality does not depend on this gate — even a
                    // compromised initiator key cannot inflate the vote supply, which the sealed
                    // mint badge caps.
                    .method("end_vote", rule!(public_key(initiator)))
                    .method("end_vote_expired", rule!(allow_all))
                    // vote_yes / vote_no / tally / resource_address are callable by anyone; they
                    // deliberately do NOT call CallerContext::transaction_signer_public_key() so
                    // that voters' transactions can be sealed with an ephemeral key (no
                    // identity).
                    .method("vote_yes", rule!(allow_all))
                    .method("vote_no", rule!(allow_all))
                    .method("tally", rule!(allow_all))
                    .method("voter_count", rule!(allow_all))
                    .method("resource_address", rule!(allow_all))
                    .default(rule!(deny_all)),
            )
            .create()
        }

        /// The vote-token resource address (so the initiator can build outputs for it).
        pub fn resource_address(&self) -> ResourceAddress {
            self.vote_resource
        }

        /// The number of eligible voters: the vote supply minted at construction. The supply can
        /// never grow after construction (the vote resource's mint rule requires a proof of a
        /// badge that is sealed in this component), so this is a hard cap on the number of votes
        /// that can ever be cast.
        pub fn voter_count(&self) -> u64 {
            self.voter_count
        }

        /// Deposit a revealed vote-token bucket into the YES vault. This method deliberately does
        /// not call `CallerContext::transaction_signer_public_key()` so the vote transaction can
        /// be sealed with an ephemeral one-time key (no voter identity).
        pub fn vote_yes(&mut self, bucket: Bucket) {
            self.validate_cast(&bucket);
            self.yes_vault.deposit(bucket);
        }

        /// Deposit a revealed vote-token bucket into the NO vault. See `vote_yes`.
        pub fn vote_no(&mut self, bucket: Bucket) {
            self.validate_cast(&bucket);
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

        /// End the vote (initiator-only). Locks the vote against further ballots and returns the
        /// final tally.
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

        /// End the vote after the voting period has expired (callable by anyone), even if not all
        /// eligible voters cast ballots. This prevents an election from being held up
        /// indefinitely by non-voting participants — or by an initiator who never returns to
        /// finalize it.
        pub fn end_vote_expired(&mut self) -> (Amount, Amount) {
            assert!(self.active, "No active vote");
            let current_epoch = Consensus::current_epoch();
            assert!(
                current_epoch > self.expires_at_epoch,
                "Voting period has not yet expired (current epoch {current_epoch}, deadline {})",
                self.expires_at_epoch,
            );
            self.active = false;
            let (yes, no) = self.tally();
            emit_event(
                "VoteEndedExpired",
                metadata!["yes" => yes.to_string(), "no" => no.to_string()],
            );
            (yes, no)
        }

        /// Shared validation for both vote methods. Guards fire in order: active flag,
        /// expiration deadline, bucket resource type, then per-ballot amount (defense in depth —
        /// construction-time mint-statement invariants already make any non-amount-1 vote
        /// unconstructible).
        fn validate_cast(&self, bucket: &Bucket) {
            assert!(self.active, "No active vote");
            let current_epoch = Consensus::current_epoch();
            assert!(
                current_epoch <= self.expires_at_epoch,
                "Voting period has expired (current epoch {current_epoch}, deadline {})",
                self.expires_at_epoch,
            );
            assert_eq!(
                bucket.resource_address(),
                self.vote_resource,
                "bucket must be the vote resource",
            );
            assert!(
                bucket.amount() == Amount::from(1u64),
                "each vote must be exactly one token",
            );
        }
    }
}
