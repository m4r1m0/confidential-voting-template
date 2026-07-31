//   Copyright 2026 The Tari Project
//   SPDX-License-Identifier: BSD-3-Clause

use std::future::Future;

use tari_ootle_transaction::{Transaction, UnsignedTransaction};

use crate::{
    Address,
    stealth::{BurnClaimKeyProvider, StealthStatementProvider},
    transaction::{TransactionSigner, TransactionStealthKeySigner},
    wallet::WalletResult,
};

/// Trait for wallets that can sign transactions on a specific network.
pub trait NetworkWallet {
    fn default_address(&self) -> &Address;

    fn sign_transaction(&self, unsigned: UnsignedTransaction)
    -> impl Future<Output = WalletResult<Transaction>> + Send;
}

/// A key provider that can sign transactions, derive stealth keys, produce stealth transfer
/// statements, and claim Layer 1 burns. Automatically implemented for any type implementing all
/// constituent traits.
///
/// On the stealth transfer path every method here takes and returns public material only — signatures
/// and statements, never keys or masks — so an implementor's key material never has to leave it. That
/// is what allows a provider backed by a wallet daemon or a hardware wallet.
///
/// [`BurnClaimKeyProvider`] is the exception and is local-custody only: it hands out both the key that
/// seals a burn claim and the burn output's mask. A remote provider cannot satisfy it as it stands.
pub trait WalletKeyProvider:
    TransactionSigner + TransactionStealthKeySigner + StealthStatementProvider + BurnClaimKeyProvider
{
}

impl<T> WalletKeyProvider for T where T: TransactionSigner + TransactionStealthKeySigner + StealthStatementProvider + BurnClaimKeyProvider
{}
