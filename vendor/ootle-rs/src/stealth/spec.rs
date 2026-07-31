//   Copyright 2026 The Tari Project
//   SPDX-License-Identifier: BSD-3-Clause

use std::{num::NonZeroU64, ops::Not};

use indexmap::IndexSet;
use tari_crypto::ristretto::RistrettoPublicKey;
use tari_ootle_common_types::engine_types::crypto::OutputBody;
use tari_ootle_wallet_crypto::{memo::Memo, pay_to::PayTo};
use tari_template_lib_types::{
    Amount,
    EncryptedData,
    ResourceAddress,
    crypto::{PedersenCommitmentBytes, UtxoTag},
    stealth::{SpendCondition, StealthInput, TemplateFunction},
};

use crate::Address;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct StealthSignerRequirement {
    signer: Address,
    public_nonce: RistrettoPublicKey,
}

impl StealthSignerRequirement {
    pub fn new(signer: Address, public_nonce: RistrettoPublicKey) -> Self {
        Self { signer, public_nonce }
    }

    pub fn signer(&self) -> &Address {
        &self.signer
    }

    pub fn public_nonce(&self) -> &RistrettoPublicKey {
        &self.public_nonce
    }
}

/// Specifies the signature requirements for a stealth transfer transaction.
/// This aims to capture the invariants around which signers are required to sign a transaction to either provider the
/// necessary access or to stealth inputs and/or substate components. If no access is required to substate components,
/// the public keys appear to be ephemeral to any outside observer. If no input access nor substate access is required,
/// an ephemeral key can be used to seal the transaction.
#[derive(Debug, Clone)]
pub struct SignatureRequirements {
    required_signers: IndexSet<StealthSignerRequirement>,
    must_sign_with_account_key: bool,
    seal_signer: Option<StealthSignerRequirement>,
}

impl SignatureRequirements {
    /// Creates a new `SignatureSpec` where the account key must sign, along with the provided required signers.
    /// The seal signer is always None, meaning users should sign with some account key.
    pub fn new_must_sign_with_account_key(required_signers: IndexSet<StealthSignerRequirement>) -> Self {
        Self {
            required_signers,
            must_sign_with_account_key: true,
            seal_signer: None,
        }
    }

    /// A requirement where the wallet's account key seals the transaction and no stealth signers are derived. The
    /// account key is the seal signer only (`is_seal_signer_authorized` stays false when authorizations are attached),
    /// so its badge is not added to the auth scope. Use this when every authorization is supplied externally — e.g. a
    /// script-path `AccessRule` leaf whose keys the wallet does not own (adaptor-signature co-signers) — so the seal
    /// signer, and hence the authorization message, is fixed and known before the authorizations are produced.
    pub fn account_key_seal() -> Self {
        Self::new_must_sign_with_account_key(IndexSet::new())
    }

    /// Creates a new `SignatureSpec` with the provided required signers and an optional seal signer.
    /// The account key is not required to sign the transaction. If there are no required signers, an ephemeral key
    /// will be used to seal the transaction.
    pub fn new_opt_with_seal_signer(
        required_signers: IndexSet<StealthSignerRequirement>,
        seal_signer: Option<StealthSignerRequirement>,
    ) -> Self {
        Self {
            required_signers,
            must_sign_with_account_key: false,
            seal_signer,
        }
    }

    pub fn must_sign_with_account_key(&self) -> bool {
        self.must_sign_with_account_key
    }

    pub fn can_sign_with_ephemeral_key(&self) -> bool {
        !self.must_sign_with_account_key && self.required_signers.is_empty() && self.seal_signer.is_none()
    }

    /// Returns the seal signer to be used for the transaction.
    /// If `must_sign_with_account_key()` is true, returns None.
    /// If `must_sign_with_account_key()` is false, and `can_sign_with_ephemeral_key()` is true, returns None
    /// If `must_sign_with_account_key()` is false, and `can_sign_with_ephemeral_key()` is false, returns the seal
    /// signer if set, otherwise returns the first required signer.
    pub fn seal_signer(&self) -> Option<&StealthSignerRequirement> {
        self.must_sign_with_account_key
            .not()
            .then(|| self.seal_signer.as_ref().or_else(|| self.required_signers.first()))
            .flatten()
    }

    pub fn other_signers(&self) -> impl Iterator<Item = &StealthSignerRequirement> {
        // Skip the first signer if must_sign_with_account_key is true and seal signer is not set because that signer is
        // used as the seal signer
        let skip = usize::from(!self.must_sign_with_account_key && self.seal_signer.is_none());
        self.required_signers.iter().skip(skip)
    }

    pub fn len(&self) -> usize {
        self.required_signers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.required_signers.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct Output {
    pub destination: Address,
    pub amount: NonZeroU64,
    pub resource_address: ResourceAddress,
    pub resource_view_key: Option<RistrettoPublicKey>,
    pub memo: Option<Memo>,
    pub pay_to: PayTo,
    pub utxo_tag: Option<UtxoTag>,
    pub minimum_value_promise: u64,
}

impl Output {
    pub fn new(destination: Address, resource_address: ResourceAddress, amount: NonZeroU64) -> Self {
        Self {
            destination,
            amount,
            resource_address,
            resource_view_key: None,
            memo: None,
            pay_to: PayTo::default(),
            utxo_tag: None,
            minimum_value_promise: 0,
        }
    }

    pub fn with_resource_view_key(mut self, resource_view_key: RistrettoPublicKey) -> Self {
        self.resource_view_key = Some(resource_view_key);
        self
    }

    pub fn with_memo(mut self, memo: Memo) -> Self {
        self.memo = Some(memo);
        self
    }

    /// Convenience method to create a text memo.
    ///
    /// # Panics
    /// Panics if the message is too long to fit in a memo.
    pub fn with_memo_message<T: Into<Box<str>>>(self, message: T) -> Self {
        self.with_memo(Memo::new_message(message).expect("Memo message too long"))
    }

    pub fn with_pay_to(mut self, pay_to: PayTo) -> Self {
        self.pay_to = pay_to;
        self
    }

    /// Gate this output's spend on a stateless WASM predicate (a single-leaf `TemplateFunction` condition tree). The
    /// value is still encrypted to `destination` so the recipient can discover and decrypt it; spending requires
    /// revealing and satisfying `template_function`.
    pub fn with_spend_script(self, template_function: TemplateFunction) -> Self {
        self.with_pay_to(PayTo::TemplateFunction(template_function))
    }

    /// Gate this output's spend on a condition tree (MAST) of alternative spend conditions. The output commits the
    /// Merkle root over `conditions`; a spender later reveals exactly ONE leaf plus an inclusion proof. Each leaf may
    /// be a native access rule, a WASM predicate ([`TemplateFunction`]), a native
    /// [`BuiltinPredicate`](tari_template_lib_types::stealth::BuiltinPredicate) (timelock, hashlock) or covenant — and
    /// a leaf is a conjunction (logical AND) of one or more such atoms.
    pub fn with_spend_conditions(self, conditions: Vec<SpendCondition>) -> Self {
        self.with_pay_to(PayTo::Conditions(conditions))
    }

    pub fn with_utxo_tag(mut self, utxo_tag: UtxoTag) -> Self {
        self.utxo_tag = Some(utxo_tag);
        self
    }
}

/// A stealth input resolved against the network and ready for statement construction.
///
/// Resolving an input — fetching its UTXO substate, rejecting frozen or burnt ones and recovering its
/// public nonce — needs network access but no keys, so it happens on the caller's side of
/// [`StealthStatementProvider`](crate::stealth::StealthStatementProvider). What remains is
/// key-dependent: recovering the input's mask from `output`.
#[derive(Debug, Clone)]
pub struct ResolvedStealthInput {
    /// The input as it appears in the statement: the commitment being spent plus the spend witness
    /// selecting its authorisation path.
    pub input: StealthInput,
    /// The on-chain output body the input's mask is recovered from.
    pub output: OutputBody,
}

impl ResolvedStealthInput {
    pub fn new(input: StealthInput, output: OutputBody) -> Self {
        Self { input, output }
    }

    pub fn commitment(&self) -> &PedersenCommitmentBytes {
        &self.input.commitment
    }
}

/// A stealth transfer whose inputs are resolved, ready to be turned into a
/// [`StealthTransferStatement`](tari_template_lib_types::stealth::StealthTransferStatement) by a
/// [`StealthStatementProvider`](crate::stealth::StealthStatementProvider).
#[derive(Debug, Clone)]
pub struct ResolvedStealthTransferSpec {
    pub inputs: Vec<ResolvedStealthInput>,
    /// Revealed amount the transfer consumes from a bucket.
    pub revealed_input_amount: Amount,
    pub outputs: Vec<Output>,
    /// Revealed amount the transfer pays out, e.g. to cover a fee.
    pub revealed_output_amount: Amount,
}

impl ResolvedStealthTransferSpec {
    pub fn total_output_amount(&self) -> Amount {
        let stealth_output_total: Amount = self.outputs.iter().map(|o| Amount::from(o.amount.get())).sum();
        stealth_output_total + self.revealed_output_amount
    }

    /// Whether the transfer needs a balance proof. A transfer with no stealth inputs and no stealth
    /// outputs moves only revealed value and has nothing to balance.
    pub fn requires_balance_proof(&self) -> bool {
        !self.inputs.is_empty() || !self.outputs.is_empty()
    }
}

/// The claimed-funds side of an L1 burn claim, ready to be turned into a statement by
/// [`BurnClaimKeyProvider::create_burn_claim_statement`](crate::stealth::BurnClaimKeyProvider::create_burn_claim_statement).
#[derive(Debug, Clone)]
pub struct BurnClaimStatementSpec {
    /// The burn UTXO's commitment, taken from the L1 burn proof.
    pub commitment: PedersenCommitmentBytes,
    /// The L1 output's encrypted data, which the burn UTXO's mask is recovered from.
    pub encrypted_data: EncryptedData,
    /// `R`, the public nonce the L1 UTXO was burnt with.
    pub sender_offset_public_key: RistrettoPublicKey,
    /// The stealth output the claimed funds are paid into.
    pub output: Output,
    /// Revealed amount reserved to pay the claim transaction's fee.
    pub revealed_output_amount: Amount,
}

#[cfg(test)]
mod tests {
    use ootle_byte_type::ToByteType;
    use tari_crypto::{
        keys::{PublicKey, SecretKey},
        ristretto::RistrettoSecretKey,
    };

    use super::*;
    use crate::Network;

    fn signer_from_seed(seed: u8) -> StealthSignerRequirement {
        let secret = RistrettoSecretKey::from_uniform_bytes(&[seed; 64]).unwrap();
        let pk = RistrettoPublicKey::from_secret_key(&secret);
        let addr = Address::new(Network::LocalNet, pk.to_byte_type(), pk.to_byte_type());
        StealthSignerRequirement::new(addr, pk)
    }

    mod signature_requirement_invariants {
        use super::*;

        /// If `must_sign_with_account_key()` is true, returns None.
        #[test]
        fn invariant1() {
            let signer1 = signer_from_seed(1);
            let signer2 = signer_from_seed(2);
            let mut required_signers = IndexSet::new();
            required_signers.insert(signer1.clone());
            required_signers.insert(signer2.clone());

            let spec = SignatureRequirements::new_must_sign_with_account_key(required_signers);
            assert!(spec.must_sign_with_account_key());
            assert!(!spec.can_sign_with_ephemeral_key());
            assert_eq!(spec.seal_signer(), None);

            let other_signers = spec.other_signers().collect::<Vec<_>>();
            assert_eq!(other_signers, vec![&signer1, &signer2]);
        }

        /// If `must_sign_with_account_key()` is false, and `can_sign_with_ephemeral_key()` is false, returns the seal
        /// signer if set, otherwise returns the first required signer.
        #[test]
        fn invariant2() {
            let signer1 = signer_from_seed(1);
            let signer2 = signer_from_seed(2);
            let mut required_signers = IndexSet::new();
            required_signers.insert(signer1.clone());
            required_signers.insert(signer2.clone());

            let spec = SignatureRequirements::new_opt_with_seal_signer(required_signers, None);
            assert!(!spec.must_sign_with_account_key());
            assert!(!spec.can_sign_with_ephemeral_key());
            let seal_signer = spec.seal_signer();
            assert_eq!(seal_signer, Some(&signer1));

            let other_signers = spec.other_signers().collect::<Vec<_>>();
            assert_eq!(other_signers, vec![&signer2]);

            let signer3 = signer_from_seed(3);
            let mut required_signers = IndexSet::new();
            required_signers.insert(signer1.clone());
            required_signers.insert(signer3.clone());

            let spec = SignatureRequirements::new_opt_with_seal_signer(required_signers, Some(signer2.clone()));
            assert!(!spec.must_sign_with_account_key());
            assert!(!spec.can_sign_with_ephemeral_key());
            let seal_signer = spec.seal_signer();
            assert_eq!(seal_signer, Some(&signer2));

            let other_signers = spec.other_signers().collect::<Vec<_>>();
            assert_eq!(other_signers, vec![&signer1, &signer3]);
        }

        /// If `must_sign_with_account_key()` is false, and `can_sign_with_ephemeral_key()` is true, returns None
        #[test]
        fn invariant3() {
            // Case 1: seal signer is set
            let spec = SignatureRequirements::new_opt_with_seal_signer(Default::default(), None);
            assert!(!spec.must_sign_with_account_key());
            assert!(spec.can_sign_with_ephemeral_key());
            let seal_signer = spec.seal_signer();
            assert_eq!(seal_signer, None);
            assert_eq!(spec.other_signers().next(), None);
        }
    }
}
