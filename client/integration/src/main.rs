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
    const_nonzero_u64,
    default_indexer_url,
    key_provider::PrivateKeyProvider,
    provider::{PendingTransaction, ProviderBuilder, WalletProvider},
    stealth::{Output, SignatureRequirements, StealthSignerRequirement, StealthTransfer},
    template_types::{
        Amount, ComponentAddress, ResourceAddress, UtxoAddress,
        constants::{TARI, TARI_TOKEN},
    },
    transaction::TransactionSigner,
    wallet::OotleWallet,
};
use std::time::Duration;
use tari_crypto::ristretto::RistrettoPublicKey;
use tari_ootle_transaction::args;

const WASM_PATH: &str = "target/wasm32-unknown-unknown/release/confidential_voting.wasm";
const VOTER_COUNT: usize = 3;
/// Per-voter: revealed TARI consumed to fund a stealth TARI UTXO for unlinkable fee payment.
const CONVERT_AMOUNT: u64 = 1 * TARI;
const CONVERT_FEE: u64 = 50_000;
const TARI_UTXO_VALUE: u64 = CONVERT_AMOUNT - CONVERT_FEE;
/// Fee paid (from the stealth TARI UTXO) for each voter's private ballot transaction.
const VOTE_FEE: u64 = 50_000;
const TARI_CHANGE: u64 = TARI_UTXO_VALUE - VOTE_FEE;

/// true = vote_yes, false = vote_no. Two yes, one no -> tally (2, 1).
const VOTE_CHOICES: [bool; VOTER_COUNT] = [true, true, false];

async fn wait(pending: &PendingTransaction, label: &str) -> Result<()> {
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

#[tokio::main]
async fn main() -> Result<()> {
    let network = Network::Esmeralda;

    // ───────────────────────── Initiator ─────────────────────────
    let init_secret = PrivateKeyProvider::random(network);
    let init_address = init_secret.address().clone();
    let init_account = init_address.to_account_address();
    let init_wallet = OotleWallet::from(init_secret);
    println!("Initiator: {init_address}\nAccount: {init_account}");

    let mut provider = ProviderBuilder::new()
        .wallet(init_wallet)
        .connect_with_transaction_timeout(default_indexer_url(network), Duration::from_secs(120))
        .await?;
    println!("Connected to indexer");

    // 1. Faucet
    println!("\n[1] Initiator faucet...");
    let unsigned = IFaucet::new(&provider)
        .take_faucet_funds()
        .pay_fee(5_000u64)
        .prepare()
        .await?;
    let tx = TransactionRequest::default()
        .with_transaction(unsigned)
        .build(provider.wallet())
        .await?;
    wait(&provider.send_transaction(tx).await?, "faucet").await?;

    // 2. Publish template
    println!("\n[2] Publish template...");
    let wasm = std::fs::read(WASM_PATH).with_context(|| format!("read {WASM_PATH}"))?;
    let unsigned = IAccount::new(&provider)
        .publish_template(wasm)
        .pay_fee(5_000_000u64)
        .prepare()
        .await?;
    let tx = TransactionRequest::default()
        .with_transaction(unsigned)
        .build(provider.wallet())
        .await?;
    let pending = provider.send_transaction(tx).await?;
    wait(&pending, "publish").await?;
    let receipt = pending.get_receipt().await?;
    let template_addr = receipt
        .diff_summary
        .upped
        .iter()
        .find_map(|s| s.substate_id.as_template())
        .context("no template addr")?
        .as_template_address();
    println!("  template: {template_addr}");

    // 3. Create component (pre-allocate vote resource so the mint statement can reference it)
    println!("\n[3] Create component...");
    let unsigned = IComponent::new(&provider)
        .then(|b| b.allocate_resource_address("vote_res"))
        .call_function(template_addr, "new", args![Workspace("vote_res")])
        .pay_fee(50_000u64)
        .prepare()
        .await?;
    let tx = TransactionRequest::default()
        .with_transaction(unsigned)
        .build(provider.wallet())
        .await?;
    let pending = provider.send_transaction(tx).await?;
    wait(&pending, "create").await?;
    let receipt = pending.get_receipt().await?;
    let component: ComponentAddress = receipt
        .diff_summary
        .upped
        .iter()
        .find_map(|s| s.substate_id.as_component_address())
        .context("no component addr")?;
    let vote_resource: ResourceAddress = receipt
        .diff_summary
        .upped
        .iter()
        .find_map(|s| s.substate_id.as_resource_address().filter(|a| *a != TARI_TOKEN))
        .context("no resource addr")?;
    println!("  component: {component}\n  vote resource: {vote_resource}");

    // 4. Pre-create voter keypairs so the mint can address one stealth output per voter.
    //    Wallets are held and moved into per-voter providers later (OotleWallet is Clone-able but
    //    we move it to avoid cloning key material).
    let mut voter_wallets: Vec<(OotleWallet, Address)> = Vec::with_capacity(VOTER_COUNT);
    for i in 0..VOTER_COUNT {
        let secret = PrivateKeyProvider::random(network);
        let addr = secret.address().clone();
        println!("  voter {i} address: {addr}");
        voter_wallets.push((OotleWallet::from(secret), addr));
    }
    let voter_addresses: Vec<Address> = voter_wallets.iter().map(|(_, a)| a.clone()).collect();

    // 5. Build the mint statement: 3 stealth vote UTXOs (amount-1 each), one per voter's one-time key.
    println!("\n[5] Build mint statement ({VOTER_COUNT} stealth vote UTXOs)...");
    let mut mint_builder =
        StealthTransfer::new(vote_resource, &provider).spend_revealed_input(VOTER_COUNT as u64);
    for addr in &voter_addresses {
        mint_builder = mint_builder.to_stealth_output(Output::new(
            addr.clone(),
            vote_resource,
            const_nonzero_u64!(1),
        ));
    }
    let (mint_statement, _) = mint_builder.prepare().await?;
    // Capture each voter's (commitment, sender_public_nonce) in-process — the initiator passes these
    // to each voter so they can build their StealthSignerRequirement. A voter spends its UTXO by
    // deriving the one-time secret from its own account_secret + this nonce (stealth-address DH).
    let vote_utxos = mint_statement.stealth_outputs().to_vec();
    for (i, u) in vote_utxos.iter().enumerate() {
        println!("  voter {i} vote UTXO commitment: {}", u.commitment());
    }

    // 6. initiate_vote — the template mints `voter_count` revealed tokens and converts them into the
    //    per-voter stealth UTXOs described by `mint_statement`.
    println!("\n[6] initiate_vote({VOTER_COUNT}, mint_statement)...");
    let unsigned = IComponent::new(&provider)
        .call_method(component, "initiate_vote", args![VOTER_COUNT as u64, mint_statement])
        .pay_fee(50_000u64)
        .prepare()
        .await?;
    let tx = TransactionRequest::default()
        .with_transaction(unsigned)
        .build(provider.wallet())
        .await?;
    wait(&provider.send_transaction(tx).await?, "initiate_vote").await?;

    // ───────────────────────── Voters ─────────────────────────
    for (i, (wallet, voter_address)) in voter_wallets.into_iter().enumerate() {
        let vote_yes = VOTE_CHOICES[i];
        let method = if vote_yes { "vote_yes" } else { "vote_no" };
        let label = if vote_yes { "YES" } else { "NO" };
        println!("\n[Voter {i}] cast {label} (addr {voter_address})");

        let vote_utxo = &vote_utxos[i];
        let vote_commitment = vote_utxo.commitment().clone();
        let vote_nonce: RistrettoPublicKey = vote_utxo
            .output
            .sender_public_nonce
            .try_from_byte_type()
            .expect("valid vote nonce");

        let voter_account = voter_address.to_account_address();
        let mut provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_with_transaction_timeout(default_indexer_url(network), Duration::from_secs(120))
            .await?;

        // V.1 Faucet
        println!("  [V{i}.1] Faucet...");
        let unsigned = IFaucet::new(&provider)
            .take_faucet_funds()
            .pay_fee(5_000u64)
            .prepare()
            .await?;
        let tx = TransactionRequest::default()
            .with_transaction(unsigned)
            .build(provider.wallet())
            .await?;
        wait(&provider.send_transaction(tx).await?, &format!("voter{i} faucet")).await?;

        // V.2 Convert revealed TARI -> stealth TARI UTXO (for unlinkable fee payment).
        println!("  [V{i}.2] Convert revealed TARI -> stealth TARI UTXO...");
        let (convert_transfer, _) = StealthTransfer::new(TARI_TOKEN, &provider)
            .spend_revealed_input(CONVERT_AMOUNT)
            .to_stealth_output(Output::new(
                voter_address.clone(),
                TARI_TOKEN,
                const_nonzero_u64!(TARI_UTXO_VALUE),
            ))
            .to_revealed_output(CONVERT_FEE)
            .prepare()
            .await?;
        let tari_utxo = convert_transfer.stealth_outputs()[0].clone();
        let tari_commitment = tari_utxo.commitment().clone();
        let unsigned = IComponent::new(&provider)
            .want_vault_for(voter_account, TARI_TOKEN, true)
            .then(|b| {
                b.with_fee_instructions_builder(|fb| {
                    fb.call_method(voter_account, "withdraw", args![TARI_TOKEN, Amount::from(CONVERT_AMOUNT)])
                        .put_last_instruction_output_on_workspace("w")
                        .stealth_transfer_with_input_bucket(TARI_TOKEN, convert_transfer, "w")
                        .put_last_instruction_output_on_workspace("convfee")
                        .pay_fee_from_bucket("convfee")
                })
            })
            .prepare()
            .await?;
        let tx = TransactionRequest::default()
            .with_transaction(unsigned)
            .build(provider.wallet())
            .await?;
        wait(&provider.send_transaction(tx).await?, &format!("voter{i} convert")).await?;

        // V.3 PRIVATE two-input spend: vote UTXO -> vault (vote_yes/vote_no) + TARI UTXO -> fee.
        //    Both stealth inputs are sealed with the vote one-time key (P_seal); the TARI input is an
        //    additional authorization. Uses the patched create_authorizations (P_seal, not K).
        println!("  [V{i}.3] Private spend: vote UTXO -> {method} + TARI UTXO -> fee...");
        let (vote_spend, _) = StealthTransfer::new(vote_resource, &provider)
            .spend_stealth_input(voter_address.clone(), vote_commitment.clone())
            .to_revealed_output(1u64)
            .prepare()
            .await?;
        let (tari_spend, _) = StealthTransfer::new(TARI_TOKEN, &provider)
            .spend_stealth_input(voter_address.clone(), tari_commitment.clone())
            .to_revealed_output(VOTE_FEE)
            .to_stealth_output(Output::new(
                voter_address.clone(),
                TARI_TOKEN,
                const_nonzero_u64!(TARI_CHANGE),
            ))
            .prepare()
            .await?;

        let tari_nonce: RistrettoPublicKey = tari_utxo
            .output
            .sender_public_nonce
            .try_from_byte_type()
            .expect("valid tari nonce");
        let vote_signer = StealthSignerRequirement::new(voter_address.clone(), vote_nonce);
        let tari_signer = StealthSignerRequirement::new(voter_address.clone(), tari_nonce);
        let mut signers = IndexSet::new();
        signers.insert(tari_signer);
        // Seal with the vote one-time key; TARI is the additional (non-seal) authorization.
        let combined_req = SignatureRequirements::new_opt_with_seal_signer(signers, Some(vote_signer));

        let unsigned = IComponent::new(&provider)
            .want_all_vaults(component)
            .then(|b| {
                b.stealth_transfer(vote_resource, vote_spend)
                    .put_last_instruction_output_on_workspace("vote")
                    .add_input(vote_resource)
                    .add_input(UtxoAddress::new(vote_resource, vote_commitment.into()))
                    .add_input(TARI_TOKEN)
                    .add_input(UtxoAddress::new(TARI_TOKEN, tari_commitment.into()))
                    .with_fee_instructions_builder(|fb| {
                        fb.stealth_transfer(TARI_TOKEN, tari_spend)
                            .put_last_instruction_output_on_workspace("fees")
                            .pay_fee_from_bucket("fees")
                    })
            })
            .call_method(component, method, args![Workspace("vote")])
            .prepare()
            .await?;

        let authorizer = provider.wallet().stealth_authorizer(combined_req);
        let dry = provider
            .sign_and_send_dry_run_with(&authorizer, unsigned.clone())
            .await?;
        dry.expect_success();
        println!("  dry-run OK, est fee: {}", dry.finalize.fee_receipt.total_fees_charged());
        let auths = authorizer.create_authorizations(&unsigned).await?;
        let tx = TransactionRequest::default()
            .with_transaction(unsigned)
            .with_authorizations(auths)
            .build(&authorizer)
            .await?;
        wait(&provider.send_transaction(tx).await?, &format!("voter{i} {method}")).await?;
    }

    // ───────────────────────── Tally ─────────────────────────
    println!("\n[Tally] tally()...");
    let unsigned = IComponent::new(&provider)
        .call_method(component, "tally", args![])
        .pay_fee(5_000u64)
        .prepare()
        .await?;
    let tx = TransactionRequest::default()
        .with_transaction(unsigned)
        .build(provider.wallet())
        .await?;
    let pending = provider.send_transaction(tx).await?;
    wait(&pending, "tally").await?;
    let receipt = pending.get_receipt().await?;
    for ev in receipt.events.iter() {
        println!("  event: {} {{{}}}", ev.topic(), ev.payload());
    }

    println!("\nINTEGRATION COMPLETE: 3-voter confidential vote validated (2 yes, 1 no expected).");
    Ok(())
}
