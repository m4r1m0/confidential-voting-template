use anyhow::{Context, Result};
use indexmap::IndexSet;
use ootle_byte_type::FromByteType;
use ootle_rs::{
    ToAccountAddress, TransactionOutcome, TransactionRequest,
    builtin_templates::{
        component::{IComponent, TransactionBuildable},
        faucet::IFaucet,
        account::IAccount,
        UnsignedTransactionBuilder,
    },
    const_nonzero_u64,
    default_indexer_url,
    key_provider::PrivateKeyProvider,
    provider::{PendingTransaction, ProviderBuilder, WalletProvider},
    stealth::{Output, SignatureRequirements, StealthSignerRequirement, StealthTransfer},
    template_types::{
        constants::{TARI, TARI_TOKEN},
        Amount, ComponentAddress, ResourceAddress, UtxoAddress,
    },
    transaction::TransactionSigner,
    wallet::{NetworkWallet, OotleWallet}, Network,
};
use std::time::Duration;
use tari_crypto::ristretto::RistrettoPublicKey;
use tari_ootle_transaction::{args, Transaction};

const WASM_PATH: &str = "target/wasm32-unknown-unknown/release/confidential_voting.wasm";
const CONVERT_AMOUNT: u64 = 1 * TARI;
const CONVERT_FEE: u64 = 50_000;
const TARI_UTXO_VALUE: u64 = CONVERT_AMOUNT - CONVERT_FEE;
const VOTE_FEE: u64 = 50_000;
const TARI_CHANGE: u64 = TARI_UTXO_VALUE - VOTE_FEE;

async fn wait(pending: &PendingTransaction, label: &str) -> Result<()> {
    print!("  {label}: pending {}... ", pending.tx_id());
    let outcome = pending.watch().await?;
    match outcome {
        TransactionOutcome::Commit => println!("COMMITTED"),
        other => { println!("FAILED: {other:?}"); anyhow::bail!("{label} failed: {other:?}"); }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let network = Network::Esmeralda;
    let secret = PrivateKeyProvider::random(network);
    let sender_address = secret.address().clone();
    let account_component = sender_address.to_account_address();
    let wallet = OotleWallet::from(secret);
    println!("Wallet: {sender_address}\nAccount: {account_component}");

    let mut provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_with_transaction_timeout(default_indexer_url(network), Duration::from_secs(120))
        .await?;
    println!("Connected to indexer");

    // 1. Faucet
    println!("[1] Faucet...");
    let unsigned = IFaucet::new(&provider).take_faucet_funds().pay_fee(5000u64).prepare().await?;
    let tx = TransactionRequest::default().with_transaction(unsigned).build(provider.wallet()).await?;
    wait(&provider.send_transaction(tx).await?, "faucet").await?;

    // 2. Convert 1 revealed TARI -> stealth TARI UTXO to self (for unlinkable fee payment)
    println!("[2] Convert revealed TARI -> stealth TARI UTXO...");
    let (convert_transfer, _) = StealthTransfer::new(TARI_TOKEN, &provider)
        .spend_revealed_input(CONVERT_AMOUNT)
        .to_stealth_output(Output::new(sender_address.clone(), TARI_TOKEN, const_nonzero_u64!(TARI_UTXO_VALUE)))
        .to_revealed_output(CONVERT_FEE)
        .prepare().await?;
    let tari_utxo = convert_transfer.stealth_outputs()[0].clone();
    let tari_commitment = tari_utxo.commitment().clone();
    let unsigned = IComponent::new(&provider)
        .want_vault_for(account_component, TARI_TOKEN, true)
        .then(|b| b.with_fee_instructions_builder(|fb| fb
            .call_method(account_component, "withdraw", args![TARI_TOKEN, Amount::from(CONVERT_AMOUNT)])
            .put_last_instruction_output_on_workspace("w")
            .stealth_transfer_with_input_bucket(TARI_TOKEN, convert_transfer, "w")
            .put_last_instruction_output_on_workspace("convfee")
            .pay_fee_from_bucket("convfee")))
        .prepare().await?;
    let tx = TransactionRequest::default().with_transaction(unsigned).build(provider.wallet()).await?;
    wait(&provider.send_transaction(tx).await?, "convert").await?;
    println!("  stealth TARI UTXO commitment: {tari_commitment}");

    // 3. Publish template
    println!("[3] Publish template...");
    let wasm = std::fs::read(WASM_PATH).with_context(|| format!("read {WASM_PATH}"))?;
    let unsigned = IAccount::new(&provider).publish_template(wasm).pay_fee(5_000_000u64).prepare().await?;
    let tx = TransactionRequest::default().with_transaction(unsigned).build(provider.wallet()).await?;
    let pending = provider.send_transaction(tx).await?;
    wait(&pending, "publish").await?;
    let receipt = pending.get_receipt().await?;
    let template_addr = receipt.diff_summary.upped.iter()
        .find_map(|s| s.substate_id.as_template()).context("no template addr")?.as_template_address();
    println!("  template: {template_addr}");

    // 4. Create component (pre-allocate vote resource)
    println!("[4] Create component...");
    let unsigned = IComponent::new(&provider)
        .then(|b| b.allocate_resource_address("vote_res"))
        .call_function(template_addr, "new", args![Workspace("vote_res")])
        .pay_fee(50_000u64)
        .prepare().await?;
    let tx = TransactionRequest::default().with_transaction(unsigned).build(provider.wallet()).await?;
    let pending = provider.send_transaction(tx).await?;
    wait(&pending, "create").await?;
    let receipt = pending.get_receipt().await?;
    let component: ComponentAddress = receipt.diff_summary.upped.iter()
        .find_map(|s| s.substate_id.as_component_address()).context("no component addr")?;
    let vote_resource: ResourceAddress = receipt.diff_summary.upped.iter()
        .find_map(|s| s.substate_id.as_resource_address().filter(|a| *a != TARI_TOKEN)).context("no resource addr")?;
    println!("  component: {component}\n  vote resource: {vote_resource}");

    // 5. Mint 1 custom stealth vote UTXO to self
    println!("[5] Mint 1 stealth vote UTXO to self...");
    let (mint_transfer, _) = StealthTransfer::new(vote_resource, &provider)
        .spend_revealed_input(1u64)
        .to_stealth_output(Output::new(sender_address.clone(), vote_resource, const_nonzero_u64!(1)))
        .prepare().await?;
    let vote_utxo = mint_transfer.stealth_outputs()[0].clone();
    let vote_commitment = vote_utxo.commitment().clone();
    let unsigned = IComponent::new(&provider)
        .call_method(component, "mint_to_recipients", args![Amount::from(1u64), mint_transfer])
        .pay_fee(50_000u64)
        .prepare().await?;
    let tx = TransactionRequest::default().with_transaction(unsigned).build(provider.wallet()).await?;
    wait(&provider.send_transaction(tx).await?, "mint").await?;
    println!("  vote UTXO commitment: {vote_commitment}");

    // 6. PRIVATE spend: vote UTXO (-> deposit_vote) + TARI UTXO (-> fee), ephemeral-sealed.
    //    Two stealth inputs in one tx. Uses the patched create_authorizations (P_seal, not K).
    println!("[6] Private spend: vote UTXO -> vault + TARI UTXO -> fee (ephemeral seal)...");
    let (vote_spend, _) = StealthTransfer::new(vote_resource, &provider)
        .spend_stealth_input(sender_address.clone(), vote_commitment.clone())
        .to_revealed_output(1u64)
        .prepare().await?;
    let (tari_spend, _) = StealthTransfer::new(TARI_TOKEN, &provider)
        .spend_stealth_input(sender_address.clone(), tari_commitment.clone())
        .to_revealed_output(VOTE_FEE)
        .to_stealth_output(Output::new(sender_address.clone(), TARI_TOKEN, const_nonzero_u64!(TARI_CHANGE)))
        .prepare().await?;

    let vote_nonce: RistrettoPublicKey = vote_utxo.output.sender_public_nonce.try_from_byte_type().expect("valid vote nonce");
    let tari_nonce: RistrettoPublicKey = tari_utxo.output.sender_public_nonce.try_from_byte_type().expect("valid tari nonce");
    let vote_signer = StealthSignerRequirement::new(sender_address.clone(), vote_nonce);
    let tari_signer = StealthSignerRequirement::new(sender_address.clone(), tari_nonce);
    let mut signers = IndexSet::new();
    signers.insert(tari_signer);
    // Seal with the vote one-time key (first stealth input, instruction order); tari is the additional auth.
    let combined_req = SignatureRequirements::new_opt_with_seal_signer(signers, Some(vote_signer));

    let unsigned = IComponent::new(&provider)
        .want_all_vaults(component)
        .then(|b| b
            .stealth_transfer(vote_resource, vote_spend)
            .put_last_instruction_output_on_workspace("vote")
            .add_input(vote_resource)
            .add_input(UtxoAddress::new(vote_resource, vote_commitment.into()))
            .add_input(TARI_TOKEN)
            .add_input(UtxoAddress::new(TARI_TOKEN, tari_commitment.into()))
            .with_fee_instructions_builder(|fb| fb
                .stealth_transfer(TARI_TOKEN, tari_spend)
                .put_last_instruction_output_on_workspace("fees")
                .pay_fee_from_bucket("fees")))
        .call_method(component, "deposit_vote", args![Workspace("vote")])
        .prepare().await?;

    let authorizer = provider.wallet().stealth_authorizer(combined_req);
    let dry = provider.sign_and_send_dry_run_with(&authorizer, unsigned.clone()).await?;
    dry.expect_success();
    println!("  dry-run OK, est fee: {}", dry.finalize.fee_receipt.total_fees_charged());
    let auths = authorizer.create_authorizations(&unsigned).await?;
    let tx = TransactionRequest::default().with_transaction(unsigned).with_authorizations(auths).build(&authorizer).await?;
    wait(&provider.send_transaction(tx).await?, "private spend+deposit").await?;

    // 7. Tally (read from receipt event)
    println!("[7] tally()...");
    let unsigned = IComponent::new(&provider).call_method(component, "tally", args![]).pay_fee(5_000u64).prepare().await?;
    let tx = TransactionRequest::default().with_transaction(unsigned).build(provider.wallet()).await?;
    let pending = provider.send_transaction(tx).await?;
    wait(&pending, "tally").await?;
    let receipt = pending.get_receipt().await?;
    for ev in receipt.events.iter() {
        println!("  event: {} {{{}}}", ev.topic(), ev.payload());
    }
    println!("SPIKE COMPLETE: custom stealth mint + PRIVATE spend-into-vault validated (patched two-input signing).");
    Ok(())
}
