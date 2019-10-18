use crate::channel_db::ChannelAddressProvider;
use crate::channel_state_store::ChannelStateStore;
use crate::channel_transaction_store::ChannelTransactionStore;
use crate::ledger_info_store::LedgerStore;
use crate::schema_db::SchemaDB;
use crypto::hash::CryptoHash;
use crypto::HashValue;
use failure::prelude::*;
use libra_types::account_address::AccountAddress;
use libra_types::account_state_blob::AccountStateWithProof;
use libra_types::crypto_proxies::LedgerInfoWithSignatures;
use libra_types::proof::AccountStateProof;
use libra_types::transaction::{TransactionInfo, TransactionToCommit, Version};
use schemadb::SchemaBatch;
use std::sync::Arc;
use storage_proto::StartupInfo;

pub struct ChannelStore<S> {
    db: Arc<S>,
    state_store: ChannelStateStore<S>,
    ledger_store: LedgerStore<S>,
    transaction_store: ChannelTransactionStore<S>,
}

impl<S> ChannelStore<S>
where
    S: SchemaDB,
{
    pub fn new(db: Arc<S>, owner_address: AccountAddress) -> Self {
        let store = ChannelStore {
            db: db.clone(),
            state_store: ChannelStateStore::new(db.clone(), owner_address),
            ledger_store: LedgerStore::new(db.clone()),
            transaction_store: ChannelTransactionStore::new(db.clone()),
        };
        store.ledger_store.bootstrap();
        store
    }

    #[cfg(test)]
    #[inline]
    pub fn db(&self) -> Arc<S> {
        self.db.clone()
    }
    #[cfg(test)]
    pub fn state_store(&self) -> &ChannelStateStore<S> {
        &self.state_store
    }
    #[cfg(test)]
    pub fn ledger_store(&self) -> &LedgerStore<S> {
        &self.ledger_store
    }
    #[cfg(test)]
    pub fn transaction_store(&self) -> &ChannelTransactionStore<S> {
        &self.transaction_store
    }
}

/// Write data part
impl<S> ChannelStore<S>
where
    S: SchemaDB + ChannelAddressProvider,
{
    pub fn save_tx(
        &self,
        txn_to_commit: &TransactionToCommit,
        version: Version,
        ledger_info_with_sigs: &Option<LedgerInfoWithSignatures>,
    ) -> Result<()> {
        if let Some(x) = ledger_info_with_sigs {
            let claimed_last_version = x.ledger_info().version();
            ensure!(
                claimed_last_version == version,
                "Transaction batch not applicable: version {}, last_version {}",
                version,
                claimed_last_version,
            );
        }
        // get write batch
        let mut schema_batch = SchemaBatch::default();
        let new_ledger_hash = self.save_tx_impl(txn_to_commit, version, &mut schema_batch)?;

        if let Some(x) = ledger_info_with_sigs {
            let expected_root_hash = x.ledger_info().transaction_accumulator_hash();
            ensure!(
                new_ledger_hash == expected_root_hash,
                "Root hash calculated doesn't match expected. {:?} vs {:?}",
                new_ledger_hash,
                expected_root_hash,
            );
            self.ledger_store.put_ledger_info(x, &mut schema_batch)?;
        }

        self.commit(schema_batch)?;

        // Once everything is successfully persisted, update the latest in-memory ledger info.
        if let Some(x) = ledger_info_with_sigs {
            self.ledger_store.set_latest_ledger_info(x.clone());
        }

        // TODO: wake pruner
        Ok(())
    }

    fn save_tx_impl(
        &self,
        tx: &TransactionToCommit,
        version: Version,
        mut schema_batch: &mut SchemaBatch,
    ) -> Result<HashValue> {
        let state_root_hash = self.state_store.put_channel_state_set(
            tx.account_states().clone(),
            version,
            &mut schema_batch,
        )?;
        // TODO: save events

        self.transaction_store
            .put_transaction(version, tx.transaction(), &mut schema_batch)?;

        let tx_info = TransactionInfo::new(
            tx.transaction().as_signed_user_txn()?.hash(),
            state_root_hash,
            HashValue::default(),
            tx.gas_used(),
            tx.major_status(),
        );
        // TODO: save to ledger store
        let new_ledger_root_hash =
            self.ledger_store
                .put_tx_info(version, &tx_info, &mut schema_batch)?;
        Ok(new_ledger_root_hash)
    }

    /// persist the batch into storage
    fn commit(&self, schema_batch: SchemaBatch) -> Result<()> {
        self.db.write_schemas(schema_batch)?;

        Ok(())
    }
}

impl<S> ChannelStore<S>
where
    S: SchemaDB + ChannelAddressProvider,
{
    /// Gets information needed from storage during the startup of the executor or state
    /// synchronizer module.
    pub fn get_startup_info(&self) -> Result<Option<StartupInfo>> {
        // Get the latest ledger info. Return None if not bootstrapped.
        let ledger_info_with_sigs = match self.ledger_store.get_latest_ledger_info_option() {
            Some(x) => x,
            None => return Ok(None),
        };
        let ledger_info = ledger_info_with_sigs.ledger_info().clone();

        let (latest_version, txn_info) = self.ledger_store.get_latest_transaction_info()?;

        let account_state_root_hash = txn_info.state_root_hash();

        let ledger_frozen_subtree_hashes = self
            .ledger_store
            .get_ledger_frozen_subtree_hashes(latest_version)?;

        Ok(Some(StartupInfo {
            ledger_info,
            latest_version,
            account_state_root_hash,
            ledger_frozen_subtree_hashes,
        }))
    }

    /// Returns the account state corresponding to the given version and account address with proof
    /// based on `ledger_version`
    pub fn get_account_state_with_proof(
        &self,
        address: AccountAddress,
        version: Version,
        ledger_version: Version,
    ) -> Result<AccountStateWithProof> {
        ensure!(
            version <= ledger_version,
            "The queried version {} should be equal to or older than ledger version {}.",
            version,
            ledger_version
        );
        let latest_version = self.get_latest_version()?;
        ensure!(
            ledger_version <= latest_version,
            "The ledger version {} is greater than the latest version currently in ledger: {}",
            ledger_version,
            latest_version
        );

        let (txn_info, txn_info_accumulator_proof) = self
            .ledger_store
            .get_transaction_info_with_proof(version, ledger_version)?;
        let (account_state_blob, sparse_merkle_proof) = self
            .state_store
            .get_account_state_with_proof_by_version(address, version)?;
        Ok(AccountStateWithProof::new(
            version,
            account_state_blob,
            AccountStateProof::new(txn_info_accumulator_proof, txn_info, sparse_merkle_proof),
        ))
    }

    /// Gets the latest version number available in the ledger.
    fn get_latest_version(&self) -> Result<Version> {
        Ok(self
            .ledger_store
            .get_latest_ledger_info()?
            .ledger_info()
            .version())
    }
}
