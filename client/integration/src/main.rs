//! CI-only end-to-end integration test for the confidential voting template.
//!
//! Runs a full 3-voter yes/no scenario on the Esmeralda testnet. For primary testing,
//! see `templates/confidential_voting/tests/test.rs` (in-process, no testnet needed).

use anyhow::{Context, Result};
use indexmap::IndexSet;
use ootle_byte_type::FromByteType;
use ootle_rs::{
    Address, Network, ToAccountAddress, TransactionOutcome, TransactionRequest,
    builtin_templates::{
        UnsignedTransactionBuilder,
        account::IAccount,
        component::{IComponent, TransactionBuildable},
        faucet::IFaucet,
    },
    default_indexer_url,
    key_provider::PrivateKeyProvider,
    provider::{IndexerProvider, PendingTransaction, ProviderBuilder, WalletProvider},
    stealth::{Output, SignatureRequirements, StealthSignerRequirement, StealthTransfer},
    template_types::{
        Amount, ComponentAddress, ResourceAddress, TemplateAddress, UtxoAddress,
        constants::{TARI, TARI_TOKEN},
        crypto::PedersenCommitmentBytes,
    },
    transaction::TransactionSigner,
    wallet::OotleWallet,
};
use std::num::NonZeroU64;
use std::time::Duration;
use tari_crypto::ristretto::RistrettoPublicKey;
use tari_ootle_transaction::{args, Epoch};

// Publish the minified release build — minify it first with:
//   wasm-opt -Oz --enable-bulk-memory target/wasm32-unknown-unknown/release/confidential_voting.wasm \
//       -o target/wasm32-unknown-unknown/release/confidential_voting.min.wasm
const WASM_PATH: &str = "target/wasm32-unknown-unknown/release/confidential_voting.min.wasm";
const VOTER_COUNT: usize = 3;
const EXPIRES_AT_EPOCH: u64 = 100_000;
const CONVERT_AMOUNT: u64 = TARI;
/// Fee paid per ballot from the stealth TARI UTXO. Bucket-paid fees are taken in full with
/// no refund — the excess is burned to the fee pool (`pay_fee_from_bucket` has no refunds),
/// so this is a flat overpay above the actual fee. The uniform amount is intentional: every
/// ballot transaction reveals the same fee, keeping all ballot txns identical in shape.
const VOTE_FEE: u64 = 50_000;

/// Scenario: voters 0 and 1 vote YES, voter 2 votes NO → tally (2, 1).
const VOTER_CHOICES: [bool; VOTER_COUNT] = [true, true, false];
const EXPECTED_TALLY: (u64, u64) = (2, 1);

type Provider = IndexerProvider<OotleWallet>;

async fn wait_for_commit(pending: &PendingTransaction, label: &str) -> Result<()> {
    print!("  {label}: pending {}... ", pending.tx_id());
    let outcome = pending.watch().await?;
    match outcome {
        TransactionOutcome::Commit => println!("COMMITTED"),
        other => {
            println!("FAILED: {other:?}");
            anyhow::bail!("{label} failed: {other:?}");
        }
    }
    Ok(())
}

/// Every transaction must carry a bounded validity window: the last epoch in which it may be
/// sequenced. Current epoch plus a margin for confirmation time.
async fn max_epoch(provider: &Provider) -> Result<Epoch> {
    Ok(Epoch(provider.get_epoch().await?.as_u64() + 10))
}

async fn faucet(provider: &mut Provider, label: &str) -> Result<()> {
    print!("\n[{label}] Faucet... ");
    let unsigned = IFaucet::new(provider, max_epoch(provider).await?)
        .take_faucet_funds()
        .pay_fee(5_000u64)
        .prepare()
        .await?;
    let tx = TransactionRequest::default()
        .with_transaction(unsigned)
        .build(provider.wallet())
        .await?;
    wait_for_commit(&provider.send_transaction(tx).await?, "faucet").await
}

/// Publish fee for the publish step. Unused fee is refunded, so overpaying costs nothing; the
/// required fee scales with WASM size (the minified ~180 KB build needs ~6M). If publishing
/// starts failing with `OnlyFeeCommit(InsufficientFeesPaid("Required fees X but Y paid"))`,
/// bump this to comfortably exceed X.
const PUBLISH_FEE: u64 = 20_000_000;

async fn publish_template(provider: &mut Provider) -> Result<TemplateAddress> {
    print!("\n[Publish] template... ");
    let wasm = std::fs::read(WASM_PATH).with_context(|| format!("read {WASM_PATH}"))?;
    let unsigned = IAccount::new(provider, max_epoch(provider).await?)
        .publish_template(wasm)
        .pay_fee(PUBLISH_FEE)
        .prepare()
        .await?;
    let tx = TransactionRequest::default()
        .with_transaction(unsigned)
        .build(provider.wallet())
        .await?;
    let pending = provider.send_transaction(tx).await?;
    wait_for_commit(&pending, "publish").await?;
    let receipt = pending.get_receipt().await?;
    let template_address = receipt
        .diff_summary
        .upped
        .iter()
        .find_map(|s| s.substate_id.as_template())
        .context("no template addr")?
        .as_template_address();
    println!("  template: {template_address}");
    Ok(template_address)
}

async fn create_and_start_vote(
    provider: &mut Provider,
    template_address: TemplateAddress,
    voter_addresses: &[Address],
) -> Result<(
    ComponentAddress,
    ResourceAddress,
    Vec<(PedersenCommitmentBytes, RistrettoPublicKey)>,
)> {
    print!("\n[Create + Start] vote... ");
    let voter_count = voter_addresses.len() as u64;

    // Build the mint statement: one stealth vote UTXO (amount-1) per voter.
    //
    // The StealthTransfer builder requires a ResourceAddress to construct, but the resulting
    // StealthTransferStatement does NOT embed it — the resource address is only used for
    // resolving stealth inputs (which we don't have; this is a revealed-input mint). So we pass
    // a placeholder address here. The real resource address is bound when the engine executes
    // the stealth_transfer instruction inside the template's `new()` constructor, which
    // receives the allocated address via the ResourceAddressAllocation parameter.
    let placeholder_resource = ResourceAddress::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000000",
    )
    .expect("valid placeholder resource address");
    let mut mint_builder =
        StealthTransfer::new(placeholder_resource, provider).spend_revealed_input(voter_count);
    for address in voter_addresses {
        let mut vote_output = Output::new(
            address.clone(),
            placeholder_resource,
            NonZeroU64::new(1).expect("non-zero"),
        );
        // The template requires every vote output to promise at least one token; the engine's
        // range proof then pins the committed value to exactly 1 (given the total and output
        // count, see `new`). The promise is public and reveals only that the vote is ≥1 — every
        // vote is exactly 1 by design, so no additional information is disclosed.
        vote_output.minimum_value_promise = 1;
        mint_builder = mint_builder.to_stealth_output(vote_output);
    }
    let (mint_statement, _) = mint_builder.prepare().await?;

    // The template asserts the same invariants at construction; check them here so a misconfigured
    // builder fails fast before submitting an unrecoverable node transaction.
    assert_eq!(
        mint_statement.stealth_outputs().len() as u64,
        voter_count,
        "mint statement must create one stealth output per voter",
    );
    assert!(
        mint_statement
            .stealth_outputs()
            .iter()
            .all(|utxo| utxo.output.minimum_value_promise >= 1),
        "each vote output must promise a minimum value of 1",
    );

    // Capture each voter's (commitment, nonce) from the mint statement so voters can
    // spend their UTXOs later.
    let vote_utxos: Vec<(PedersenCommitmentBytes, RistrettoPublicKey)> = mint_statement
        .stealth_outputs()
        .iter()
        .map(|utxo| {
            let commitment = *utxo.commitment();
            let nonce: RistrettoPublicKey = utxo
                .output
                .sender_public_nonce
                .try_from_byte_type()
                .expect("valid nonce");
            (commitment, nonce)
        })
        .collect();

    // Create the component and start the vote in a single transaction.
    let unsigned = IComponent::new(provider, max_epoch(provider).await?)
        .then(|builder| builder.allocate_resource_address("vote_res"))
        .call_function(
            template_address,
            "new",
            args![
                Workspace("vote_res"),
                voter_count,
                EXPIRES_AT_EPOCH,
                mint_statement,
            ],
        )
        .pay_fee(50_000u64)
        .prepare()
        .await?;
    let tx = TransactionRequest::default()
        .with_transaction(unsigned)
        .build(provider.wallet())
        .await?;
    let pending = provider.send_transaction(tx).await?;
    wait_for_commit(&pending, "create + start").await?;
    let receipt = pending.get_receipt().await?;
    let component = receipt
        .diff_summary
        .upped
        .iter()
        .find_map(|s| s.substate_id.as_component_address())
        .context("no component addr")?;
    // The template creates two resources: CVOTE-MINT (NonFungible, the mint badge) and CVOTE
    // (Stealth, the votes themselves). The mint statement commits to the stealth resource, so
    // pick it out of the `resource.create` events rather than guessing from the diff order.
    let vote_resource = receipt
        .events
        .iter()
        .find(|event| {
            event.topic() == "std.resource.create"
                && event.get_payload("resource_type") == Some("Stealth")
        })
        .and_then(|event| event.substate_id())
        .and_then(|s| s.as_resource_address())
        .context("no vote resource addr")?;
    println!("  component: {component}\n  vote resource: {vote_resource}");
    Ok((component, vote_resource, vote_utxos))
}

async fn convert_to_stealth_tari(
    provider: &mut Provider,
    voter_address: &Address,
) -> Result<(PedersenCommitmentBytes, RistrettoPublicKey)> {
    let voter_account = voter_address.to_account_address();
    let tari_utxo_value = CONVERT_AMOUNT - VOTE_FEE;

    let (convert_transfer, _) = StealthTransfer::new(TARI_TOKEN, provider)
        .spend_revealed_input(CONVERT_AMOUNT)
        .to_stealth_output(Output::new(
            voter_address.clone(),
            TARI_TOKEN,
            NonZeroU64::new(tari_utxo_value).expect("non-zero utxo value"),
        ))
        .to_revealed_output(VOTE_FEE)
        .prepare()
        .await?;

    let tari_utxo = &convert_transfer.stealth_outputs()[0];
    let tari_commitment = *tari_utxo.commitment();
    let tari_nonce: RistrettoPublicKey = tari_utxo
        .output
        .sender_public_nonce
        .try_from_byte_type()
        .expect("valid tari nonce");

    let unsigned = IComponent::new(provider, max_epoch(provider).await?)
        .want_vault_for(voter_account, TARI_TOKEN, true)
        .then(|builder| {
            builder.with_fee_instructions_builder(|fee_builder| {
                fee_builder
                    .call_method(
                        voter_account,
                        "withdraw",
                        args![TARI_TOKEN, Amount::from(CONVERT_AMOUNT)],
                    )
                    .put_last_instruction_output_on_workspace("withdrawn")
                    .stealth_transfer_with_input_bucket(TARI_TOKEN, convert_transfer, "withdrawn")
                    .put_last_instruction_output_on_workspace("fee_output")
                    .pay_fee_from_bucket("fee_output")
            })
        })
        .prepare()
        .await?;
    let tx = TransactionRequest::default()
        .with_transaction(unsigned)
        .build(provider.wallet())
        .await?;
    wait_for_commit(&provider.send_transaction(tx).await?, "convert").await?;

    Ok((tari_commitment, tari_nonce))
}

/// Casts a ballot via a two-input stealth spend: the vote-token UTXO is the seal input
/// (spent into `vote_yes` / `vote_no`) and a stealth TARI UTXO pays the fee. This is the
/// canonical pattern for the README's fee-from-stealth requirement — the fee MUST come from a
/// stealth TARI UTXO, never a revealed account, or the transaction links the voter's identity
/// to their vote.
#[allow(clippy::too_many_arguments)]
async fn cast_private_ballot(
    provider: &mut Provider,
    component: ComponentAddress,
    vote_resource: ResourceAddress,
    voter_address: &Address,
    vote_commitment: PedersenCommitmentBytes,
    vote_nonce: RistrettoPublicKey,
    tari_commitment: PedersenCommitmentBytes,
    tari_nonce: RistrettoPublicKey,
    is_yes: bool,
) -> Result<()> {
    let method = if is_yes { "vote_yes" } else { "vote_no" };
    let tari_change = CONVERT_AMOUNT - VOTE_FEE - VOTE_FEE;

    let (vote_spend, _) = StealthTransfer::new(vote_resource, provider)
        .spend_stealth_input(voter_address.clone(), vote_commitment)
        .to_revealed_output(1u64)
        .prepare()
        .await?;
    let (tari_spend, _) = StealthTransfer::new(TARI_TOKEN, provider)
        .spend_stealth_input(voter_address.clone(), tari_commitment)
        .to_revealed_output(VOTE_FEE)
        .to_stealth_output(Output::new(
            voter_address.clone(),
            TARI_TOKEN,
            NonZeroU64::new(tari_change).expect("non-zero change"),
        ))
        .prepare()
        .await?;

    let vote_signer = StealthSignerRequirement::new(voter_address.clone(), vote_nonce);
    let tari_signer = StealthSignerRequirement::new(voter_address.clone(), tari_nonce);
    let mut authorizers = IndexSet::new();
    authorizers.insert(tari_signer);
    // The vote-token UTXO seals the transaction (its one-time key P is the seal key) and the
    // stealth TARI fee UTXO authorizes against it.
    let signature_requirements =
        SignatureRequirements::stealth_seal_with(vote_signer, authorizers);

    let unsigned = IComponent::new(provider, max_epoch(provider).await?)
        .want_all_vaults(component)
        .then(|builder| {
            builder
                .stealth_transfer(vote_resource, vote_spend)
                .put_last_instruction_output_on_workspace("vote")
                .add_input(vote_resource)
                .add_input(UtxoAddress::new(vote_resource, vote_commitment.into()))
                .add_input(TARI_TOKEN)
                .add_input(UtxoAddress::new(TARI_TOKEN, tari_commitment.into()))
                .with_fee_instructions_builder(|fee_builder| {
                    fee_builder
                        .stealth_transfer(TARI_TOKEN, tari_spend)
                        .put_last_instruction_output_on_workspace("fees")
                        .pay_fee_from_bucket("fees")
                })
        })
        .call_method(component, method, args![Workspace("vote")])
        .prepare()
        .await?;

    let authorizer = provider.wallet().stealth_authorizer(signature_requirements);
    // Preflight (kept intentionally): dry-run the exact unsigned transaction so a
    // fee/invalidity failure aborts here, before spending real fees on-chain.
    let dry_run = provider
        .sign_and_send_dry_run_with(&authorizer, unsigned.clone())
        .await?;
    dry_run.expect_success();

    // `build` asks the authorizer for the stealth authorization signatures its inputs require
    // (committing to the seal signer's one-time public key) and seals the transaction.
    let tx = TransactionRequest::default()
        .with_transaction(unsigned)
        .build(&authorizer)
        .await?;
    wait_for_commit(&provider.send_transaction(tx).await?, method).await
}

async fn end_vote_and_read_tally(provider: &mut Provider, component: ComponentAddress) -> Result<()> {
    print!("\n[Result] end_vote()... ");
    let unsigned = IComponent::new(provider, max_epoch(provider).await?)
        .call_method(component, "end_vote", args![])
        .pay_fee(5_000u64)
        .prepare()
        .await?;
    let tx = TransactionRequest::default()
        .with_transaction(unsigned)
        .build(provider.wallet())
        .await?;
    let pending = provider.send_transaction(tx).await?;
    wait_for_commit(&pending, "end_vote").await?;
    let receipt = pending.get_receipt().await?;
    for event in receipt.events.iter() {
        println!("  event: {} {{{}}}", event.topic(), event.payload());
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let network = Network::Esmeralda;

    let init_secret = PrivateKeyProvider::random(network);
    let init_address = init_secret.address().clone();
    let init_wallet = OotleWallet::from(init_secret);
    println!("Initiator: {init_address}");

    let mut initiator_provider = ProviderBuilder::new()
        .wallet(init_wallet)
        .connect_with_transaction_timeout(default_indexer_url(network), Duration::from_secs(120))
        .await?;
    println!("Connected to indexer");

    faucet(&mut initiator_provider, "Initiator").await?;
    let template_address = publish_template(&mut initiator_provider).await?;

    let voter_wallets: Vec<(OotleWallet, Address)> = (0..VOTER_COUNT)
        .map(|i| {
            let secret = PrivateKeyProvider::random(network);
            let address = secret.address().clone();
            println!("  voter {i} address: {address}");
            (OotleWallet::from(secret), address)
        })
        .collect();
    let voter_addresses: Vec<Address> = voter_wallets.iter().map(|(_, a)| a.clone()).collect();

    let (component, vote_resource, vote_utxos) =
        create_and_start_vote(&mut initiator_provider, template_address, &voter_addresses).await?;

    for (i, (commitment, _)) in vote_utxos.iter().enumerate() {
        println!(
            "  voter {i} vote UTXO commitment: {}",
            hex::encode(commitment)
        );
    }

    for (i, (wallet, voter_address)) in voter_wallets.into_iter().enumerate() {
        let is_yes = VOTER_CHOICES[i];
        println!("\n[Voter {i}] casting ballot vote={is_yes}");

        let (vote_commitment, vote_nonce) = &vote_utxos[i];

        let mut voter_provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_with_transaction_timeout(
                default_indexer_url(network),
                Duration::from_secs(120),
            )
            .await?;

        faucet(&mut voter_provider, &format!("Voter {i}")).await?;
        let (tari_commitment, tari_nonce) =
            convert_to_stealth_tari(&mut voter_provider, &voter_address).await?;
        cast_private_ballot(
            &mut voter_provider,
            component,
            vote_resource,
            &voter_address,
            *vote_commitment,
            vote_nonce.clone(),
            tari_commitment,
            tari_nonce,
            is_yes,
        )
        .await?;
    }

    end_vote_and_read_tally(&mut initiator_provider, component).await?;

    println!(
        "\nINTEGRATION COMPLETE: 3-voter yes/no vote validated (expected tally = {:?}).",
        EXPECTED_TALLY
    );
    Ok(())
}
