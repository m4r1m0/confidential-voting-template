// In-process test suite for the confidential voting template.
//
// Primary testing happens here (no testnet needed) using tari_template_test_tooling. The
// testnet end-to-end run lives in `client/integration/src/main.rs` and is CI-only.
//
// Coverage mirrors the sibling ranked-choice template's suite:
// - Constructor invariant enforcement: zero voter count, output-count mismatch, wrong-valued
//   mint shapes ([2,0] etc. rejected via per-output minimum-value promises)
// - Adversarial casts: wrong token type while the vote is live, vote after close,
//   vote after expiration, double-spend of a stealth ballot UTXO
// - Finalization rules: non-initiator cannot end a live vote; expired votes are finalizable by
//   anyone; `end_vote_expired` cannot be called before the deadline
// - Supply-cap verification: committed resource definitions prove the mint authority is
//   permanently revoked
// - A full three-voter election, entirely in-process

use tari_template_lib::prelude::Amount;
use tari_template_lib::types::SubstateOwnerRule;
use tari_template_lib::types::access_rules::{
    AccessRule, RequireRule, ResourceAuthAction, RestrictedAccessRule, RuleRequirement, UpdateRule,
};
use tari_template_lib::types::constants::TARI_TOKEN;
use tari_template_test_tooling::TemplateTest;
use tari_template_test_tooling::byte_type::ToByteType;
use tari_template_test_tooling::crypto::{PublicKey, RistrettoPublicKey, RistrettoSecretKey};
use tari_template_test_tooling::engine_types::virtual_substate::{
    VirtualSubstate, VirtualSubstateId,
};
use tari_template_test_tooling::support::assert_error::assert_reject_reason;
use tari_template_test_tooling::support::stealth::{
    StealthSecretTransferData, generate_transfer_data, test_sender_public_nonce,
};
use tari_template_test_tooling::template_lib_types::{
    EncryptedData,
    crypto::UtxoTag,
    stealth::SpendAuthorization,
};
use tari_template_test_tooling::transaction::{Epoch, Transaction, args};
use tari_template_test_tooling::wallet_crypto::{MaskAndValue, OutputWitness, StealthOutputWitness};
use tari_template_test_tooling::wallet_crypto::stealth::create_transfer_statement;

/// Builds the mint statement for `voter_count` amount-1 vote UTXOs, each promising a minimum
/// value of 1 (the invariant `new` enforces). The returned data keeps each UTXO's mask so tests
/// can spend the UTXOs later (each vote UTXO is a key-path output whose spend key is its mask).
fn mint_votes(voter_count: u64) -> StealthSecretTransferData {
    let outputs: Vec<(u64, u64)> = (0..voter_count).map(|_| (1, 1)).collect();
    mint_votes_with_outputs(outputs)
}

/// Like `mint_votes`, but with the given per-output amounts (each with a value-1 minimum
/// promise). The returned data keeps each UTXO's mask so tests can spend the UTXOs later.
fn mint_votes_with_amounts(output_amounts: Vec<u64>) -> StealthSecretTransferData {
    mint_votes_with_outputs(output_amounts.iter().map(|&amount| (amount, 1)).collect())
}

/// Builds a mint statement with the given `(amount, minimum_value_promise)` pairs for the output
/// set, mirroring the tooling's `generate_mint_statement` but with explicit per-output promises
/// (the tooling hardcodes promise 0). The returned data keeps each UTXO's mask so tests can spend
/// the UTXOs later.
fn mint_votes_with_outputs(outputs: Vec<(u64, u64)>) -> StealthSecretTransferData {
    let masks: Vec<RistrettoSecretKey> =
        (0..outputs.len()).map(|i| RistrettoSecretKey::from(i as u64 + 1)).collect();
    let output_statements: Vec<StealthOutputWitness> = outputs
        .iter()
        .zip(&masks)
        .map(|((amount, promise), mask)| StealthOutputWitness {
            witness: OutputWitness {
                amount: *amount,
                mask: mask.clone(),
                sender_public_nonce: test_sender_public_nonce(),
                minimum_value_promise: *promise,
                encrypted_data: EncryptedData::try_from(vec![0; EncryptedData::min_size()])
                    .expect("valid encrypted data"),
                resource_view_key: None,
            },
            auth: SpendAuthorization::Key(RistrettoPublicKey::from_secret_key(mask).to_byte_type()),
            tag: UtxoTag::new(0),
        })
        .collect();

    let total: u64 = outputs.iter().map(|(amount, _)| amount).sum();
    let statement = create_transfer_statement(
        std::iter::empty(),
        Amount::from(total),
        output_statements.iter(),
        Amount::zero(),
    )
    .expect("valid transfer statement");

    StealthSecretTransferData {
        output_masks: masks,
        output_auths: vec![],
        statement,
    }
}

/// Creates a ConfidentialVote component with the given parameters and returns
/// (component_address, vote_resource_address, test, account, proof, secret).
fn create_vote(
    voter_count: u64,
    expires_at_epoch: u64,
) -> (
    tari_template_lib::types::ComponentAddress,
    tari_template_lib::types::ResourceAddress,
    TemplateTest,
    tari_template_lib::types::ComponentAddress,
    tari_template_lib::types::NonFungibleAddress,
    tari_template_test_tooling::crypto::RistrettoSecretKey,
) {
    let mut test = TemplateTest::my_crate();
    let template_address = test.get_template_address("ConfidentialVote");
    let (account, proof, secret) = test.create_funded_account();

    let mint_data = mint_votes(voter_count);

    let transaction = test
        .transaction()
        .allocate_resource_address("vote_res")
        .call_function(
            template_address,
            "new",
            args![
                Workspace("vote_res"),
                voter_count,
                expires_at_epoch,
                mint_data.statement,
            ],
        )
        .build_and_seal(&secret);

    let result = test.execute_expect_success(transaction, vec![proof.clone()]);
    let component_address = result
        .finalize
        .result
        .accept()
        .unwrap()
        .up_iter()
        .find_map(|(id, _)| id.as_component_address())
        .expect("component address");
    // Two resources are created by `new` (the vote resource and the sealed mint badge), so the
    // vote resource is identified semantically: it is the stealth resource that is not TARI (the
    // test tooling's TARI token is itself a stealth resource).
    let vote_resource = test
        .read_only_state_store()
        .get_all_resources()
        .expect("resources")
        .into_iter()
        .find(|(address, resource)| resource.resource_type().is_stealth() && *address != TARI_TOKEN)
        .map(|(address, _)| address)
        .expect("vote resource");

    (
        component_address,
        vote_resource,
        test,
        account,
        proof,
        secret,
    )
}

/// Attempts to create a vote with the given parameters, expecting failure. Returns the
/// reject reason for assertion.
fn create_vote_expect_failure(
    voter_count: u64,
    mint_data: StealthSecretTransferData,
) -> tari_template_test_tooling::engine_types::commit_result::RejectReason {
    let mut test = TemplateTest::my_crate();
    let template_address = test.get_template_address("ConfidentialVote");
    let (_account, _proof, secret) = test.create_funded_account();

    let transaction = test
        .transaction()
        .allocate_resource_address("vote_res")
        .call_function(
            template_address,
            "new",
            args![
                Workspace("vote_res"),
                voter_count,
                1000u64,
                mint_data.statement,
            ],
        )
        .build_and_seal(&secret);

    test.execute_expect_failure(transaction, vec![])
}

#[test]
fn rejects_zero_voter_count() {
    let reason = create_vote_expect_failure(0, mint_votes(0));
    assert_reject_reason(reason, "voter_count must be positive");
}

#[test]
fn rejects_output_count_mismatch() {
    for (amounts, voter_count) in [(vec![2u64], 2u64), (vec![1u64, 2u64], 3u64)] {
        // Both statements have the right TOTAL (so the total assert passes) but create too few
        // outputs for the voters: [2] merges two votes into one 2-token vote; [1,2] leaves the
        // third voter without a vote. The output-count assert fires at construction.
        let reason = create_vote_expect_failure(voter_count, mint_votes_with_amounts(amounts));
        assert_reject_reason(
            reason,
            "mint statement must create one stealth output per voter",
        );
    }
}

#[test]
fn rejects_zero_value_vote_shapes_at_construction() {
    // [2,0] with voter_count 2 has the right TOTAL (2) and the right OUTPUT COUNT (2), so it
    // passes the total and count asserts. A value-0 output can only ever be proven with a
    // minimum-value promise of 0 (any higher promise breaks the engine's range proof), so the
    // per-output promise assert in `new` fires at construction. The cast-time amount guard is
    // therefore unreachable for wrong-valued votes: no such vote can exist.
    let reason = create_vote_expect_failure(
        2,
        mint_votes_with_outputs(vec![(2u64, 1u64), (0u64, 0u64)]),
    );
    assert_reject_reason(reason, "each vote output must promise a minimum value of 1");

    // A [3,0,0] shape with voter_count 3 is rejected by the same assert: only the 3-token output
    // can promise its value, both 0-value outputs must promise 0.
    let reason = create_vote_expect_failure(
        3,
        mint_votes_with_outputs(vec![(3u64, 1u64), (0u64, 0u64), (0u64, 0u64)]),
    );
    assert_reject_reason(reason, "each vote output must promise a minimum value of 1");
}

#[test]
fn rejects_wrong_token_while_vote_active() {
    let (component, _vote_resource, mut test, account, proof, secret) =
        create_vote(1, 1000);

    // The vote is live and unexpired, so the active and expiration checks pass and the
    // resource check fires: the bucket must hold the vote token, not TARI.
    let transaction = test
        .transaction()
        .call_method(account, "withdraw", args![TARI_TOKEN, Amount::from(1u64)])
        .put_last_instruction_output_on_workspace("bucket")
        .call_method(component, "vote_yes", args![Workspace("bucket")])
        .build_and_seal(&secret);

    let reason = test.execute_expect_failure(transaction, vec![proof]);
    assert_reject_reason(reason, "bucket must be the vote resource");
}

#[test]
fn rejects_ballot_after_vote_closed() {
    let (component, _vote_resource, mut test, _account, _proof, secret) =
        create_vote(1, 1000);

    // End the vote (the creator of `new` is the initiator).
    let end_transaction = test
        .transaction()
        .call_method(component, "end_vote", args![])
        .build_and_seal(&secret);
    test.execute_expect_success(end_transaction, vec![]);

    // Attempt to cast a ballot after the vote is closed. The `assert!(self.active)` fires
    // before the resource check, so we can use any withdrawable token here.
    let transaction = test
        .transaction()
        .call_method(_account, "withdraw", args![TARI_TOKEN, Amount::from(1u64)])
        .put_last_instruction_output_on_workspace("bucket")
        .call_method(component, "vote_yes", args![Workspace("bucket")])
        .build_and_seal(&secret);

    let reason = test.execute_expect_failure(transaction, vec![]);
    assert_reject_reason(reason, "No active vote");
}

#[test]
fn rejects_ballot_after_expiration() {
    let (component, _vote_resource, mut test, account, proof, secret) =
        create_vote(1, 10);

    // Advance the epoch past the expiration.
    test.set_virtual_substate(
        VirtualSubstateId::CurrentEpoch,
        VirtualSubstate::CurrentEpoch(11),
    );

    // Attempt to cast a ballot. The active check passes, but the expiration check fires.
    // We use TARI here — the expiration assertion fires before the resource check.
    let transaction = test
        .transaction()
        .call_method(account, "withdraw", args![TARI_TOKEN, Amount::from(1u64)])
        .put_last_instruction_output_on_workspace("bucket")
        .call_method(component, "vote_no", args![Workspace("bucket")])
        .build_and_seal(&secret);

    let reason = test.execute_expect_failure(transaction, vec![proof]);
    assert_reject_reason(reason, "Voting period has expired");
}

#[test]
fn rejects_end_vote_expired_before_deadline() {
    let (component, _vote_resource, mut test, _account, _proof, secret) =
        create_vote(1, 100);

    // Epoch is still 0 (default), well before expiration at 100.
    let transaction = test
        .transaction()
        .call_method(component, "end_vote_expired", args![])
        .build_and_seal(&secret);

    let reason = test.execute_expect_failure(transaction, vec![]);
    assert_reject_reason(reason, "Voting period has not yet expired");
}

#[test]
fn anyone_can_finalize_expired_vote() {
    let (component, _vote_resource, mut test, _account, _proof, _secret) =
        create_vote(1, 0);

    // Advance the epoch past the expiration, so the vote is finalizable.
    test.set_virtual_substate(
        VirtualSubstateId::CurrentEpoch,
        VirtualSubstate::CurrentEpoch(1),
    );

    // A fresh account (not the initiator) can finalize the expired vote — `end_vote_expired` is
    // open to anyone, and the method's own assert verifies the deadline has passed.
    let (_other_account, _other_proof, other_secret) = test.create_funded_account();
    let transaction = test
        .transaction()
        .call_method(component, "end_vote_expired", args![])
        .build_and_seal(&other_secret);
    test.execute_expect_success(transaction, vec![]);
}

#[test]
fn end_vote_rejected_for_non_initiator() {
    let (component, _vote_resource, mut test, _account, _proof, secret) =
        create_vote(1, 1000);

    // A different account (not the caller of `new`) tries to end the vote. The access rule on
    // `end_vote` requires the initiator's public key.
    let (_other_account, _other_proof, other_secret) = test.create_funded_account();
    let transaction = test
        .transaction()
        .call_method(component, "end_vote", args![])
        .build_and_seal(&other_secret);
    let reason = test.execute_expect_failure(transaction, vec![]);
    assert_reject_reason(reason, "Access Denied");

    // The initiator can still end the vote.
    let transaction = test
        .transaction()
        .call_method(component, "end_vote", args![])
        .build_and_seal(&secret);
    test.execute_expect_success(transaction, vec![]);
}

#[test]
fn vote_minting_is_permanently_revoked() {
    let (component, vote_resource, test, _account, _proof, _secret) =
        create_vote(3, 1000);

    // The one-of mint badge is sealed inside the component; it is held by the component vault
    // that does not hold vote tokens.
    let store = test.read_only_state_store();
    let vaults = store
        .get_vaults_for_component(component)
        .expect("component vaults");
    let badge_resource = vaults
        .values()
        .map(|vault| *vault.resource_address())
        .find(|address| *address != vote_resource)
        .expect("badge vault");

    let vote_def = store.get_resource(&vote_resource).expect("vote resource");
    let badge_def = store.get_resource(&badge_resource).expect("badge resource");

    // Minting vote tokens requires a proof of the sealed badge, and the rule is locked so it
    // can never be changed.
    let vote_rules = vote_def.access_rules();
    assert!(matches!(
        vote_rules.get_updater(&ResourceAuthAction::Mint),
        UpdateRule::Locked,
    ));
    match vote_rules.get_access_rule(&ResourceAuthAction::Mint) {
        AccessRule::Restricted(RestrictedAccessRule::Require(RequireRule::Require(
            RuleRequirement::Resource(address),
        ))) => assert_eq!(address, &badge_resource),
        other => panic!("unexpected vote mint rule: {other:?}"),
    }
    // The vote resource is ownerless, so the resource-owner authorization path (which would
    // bypass the mint rule) is closed. Burning votes is denied outright (no one — including the
    // initiator — can ever burn vote tokens); the withdraw rule stays allow_all because the
    // constructor's mint-to-stealth conversion is authorized by it, but no template method ever
    // exposes a vote vault to callers, so it is inert.
    assert_eq!(vote_def.owner_rule(), &SubstateOwnerRule::None);
    assert_eq!(
        vote_rules.get_access_rule(&ResourceAuthAction::Burn),
        &AccessRule::DenyAll,
    );
    assert!(matches!(
        vote_rules.get_updater(&ResourceAuthAction::Burn),
        UpdateRule::Locked,
    ));

    // The badge itself can never be minted, burned, recalled, or modified, so the one badge that
    // exists at construction is the only one that will ever exist. Its withdraw rule stays
    // allow_all (creating the constructor's mint proof is authorized by it) but is inert: vaults
    // cannot be addressed by transactions, and no template method exposes the sealed badge vault.
    let badge_rules = badge_def.access_rules();
    for action in [
        ResourceAuthAction::Mint,
        ResourceAuthAction::Burn,
        ResourceAuthAction::Recall,
        ResourceAuthAction::UpdateNonFungibleData,
    ] {
        assert_eq!(badge_rules.get_access_rule(&action), &AccessRule::DenyAll);
        assert!(matches!(
            badge_rules.get_updater(&action),
            UpdateRule::Locked
        ));
    }
    assert_eq!(
        badge_rules.get_access_rule(&ResourceAuthAction::Withdraw),
        &AccessRule::AllowAll
    );
    assert!(matches!(
        badge_rules.get_updater(&ResourceAuthAction::Withdraw),
        UpdateRule::Locked
    ));
    assert_eq!(badge_def.total_supply(), Some(Amount::from(1u64)));

    // Exactly one vote per eligible voter was minted at construction, and the stored voter_count
    // matches (field index 5 = the 6th field of `ConfidentialVote`, in declaration order).
    assert_eq!(vote_def.total_supply(), Some(Amount::from(3u64)));
    let voter_count: u64 = test.extract_component_value(component, "5");
    assert_eq!(voter_count, 3);
}

// ───────────────────── End-to-end stealth-ballot election ─────────────────────
//
// Mirrors the testnet scenario in `client/integration/src/main.rs` entirely in-process
// (no testnet needed): the vote is created, voters spend their stealth vote UTXOs into
// `vote_yes` / `vote_no`, double-spending is rejected by the engine, and `end_vote`
// produces the expected (2 yes, 1 no) tally.

#[test]
fn end_to_end_three_voter_election() {
    let mut test = TemplateTest::my_crate();
    let template_address = test.get_template_address("ConfidentialVote");

    // Scenario: 3 voters → 2 yes, 1 no.
    const VOTES: [bool; 3] = [true, true, false];

    // Create the vote; the constructor mints one amount-1 vote UTXO per voter.
    let vote_mint = mint_votes(3);
    let transaction = test
        .transaction()
        .allocate_resource_address("vote_res")
        .call_function(
            template_address,
            "new",
            args![
                Workspace("vote_res"),
                3u64,
                1000u64,
                vote_mint.statement,
            ],
        )
        .build_and_seal(test.secret_key());
    let result = test.execute_expect_success(transaction, vec![]);
    let component = result
        .finalize
        .result
        .accept()
        .unwrap()
        .up_iter()
        .find_map(|(id, _)| id.as_component_address())
        .expect("component address");
    // The vote resource is the stealth resource that is not the test tooling's TARI token.
    let vote_resource = test
        .read_only_state_store()
        .get_all_resources()
        .expect("resources")
        .into_iter()
        .find(|(address, resource)| resource.resource_type().is_stealth() && *address != TARI_TOKEN)
        .map(|(address, _)| address)
        .expect("vote resource");

    // Each voter spends their vote UTXO into `vote_yes` / `vote_no`: the UTXO is a key-path
    // output whose spend key is its mask, so the spend transaction is signed with the mask (the
    // canonical in-process stealth-spend pattern).
    for (i, &is_yes) in VOTES.iter().enumerate() {
        let vote_spend = generate_transfer_data(
            [MaskAndValue {
                mask: vote_mint.output_masks[i].clone(),
                value: 1,
            }],
            0u64,
            Vec::<u64>::new(),
            1u64,
        );
        let method = if is_yes { "vote_yes" } else { "vote_no" };
        let transaction = Transaction::builder_localnet(Epoch(100))
            .stealth_transfer(vote_resource, vote_spend.statement)
            .put_last_instruction_output_on_workspace("vote")
            .call_method(component, method, args![Workspace("vote")])
            .finish()
            .add_signer(&test.to_public_key_bytes(), &vote_mint.output_masks[i])
            .seal(test.secret_key());
        test.execute_expect_success(transaction, vec![]);
    }

    // A stealth UTXO can only be spent once: re-spending voter 0's vote must fail.
    let double_spend = generate_transfer_data(
        [MaskAndValue {
            mask: vote_mint.output_masks[0].clone(),
            value: 1,
        }],
        0u64,
        Vec::<u64>::new(),
        1u64,
    );
    let transaction = Transaction::builder_localnet(Epoch(100))
        .stealth_transfer(vote_resource, double_spend.statement)
        .put_last_instruction_output_on_workspace("vote")
        .call_method(component, "vote_yes", args![Workspace("vote")])
        .finish()
        .add_signer(&test.to_public_key_bytes(), &vote_mint.output_masks[0])
        .seal(test.secret_key());
    test.execute_expect_failure(transaction, vec![]);

    // End the vote: the tally must be exactly (2 yes, 1 no).
    let secret = test.secret_key();
    let transaction = test
        .transaction()
        .call_method(component, "end_vote", args![])
        .build_and_seal(&secret);
    let result = test.execute_expect_success(transaction, vec![]);
    let result_event = result
        .finalize
        .events
        .iter()
        .find(|event| event.topic().ends_with(".VoteEnded"))
        .expect("final tally event");
    assert_eq!(result_event.payload().get("yes"), Some("2"));
    assert_eq!(result_event.payload().get("no"), Some("1"));
}
