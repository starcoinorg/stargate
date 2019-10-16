use crate::channel_db::ChannelAddressProvider;
use crate::channel_state_store::ChannelStateStore;
use crate::channel_transaction_store::ChannelTransactionStore;
use crate::ledger_info_store::LedgerStore;
use crate::schema_db::SchemaDB;
use crypto::hash::CryptoHash;
use crypto::HashValue;
use failure::prelude::*;
use libra_types::account_address::AccountAddress;
use libra_types::crypto_proxies::LedgerInfoWithSignatures;
use libra_types::transaction::{TransactionInfo, TransactionToCommit, Version};
use schemadb::SchemaBatch;
use std::sync::Arc;

pub struct ChannelStore<S> {
    db: Arc<S>,
    state_store: ChannelStateStore<S>,
    ledger_info_store: LedgerStore<S>,
    transaction_store: ChannelTransactionStore<S>,
}

impl<S> ChannelStore<S>
where
    S: SchemaDB,
{
    pub fn new(db: Arc<S>, owner_address: AccountAddress) -> Self {
        ChannelStore {
            db: db.clone(),
            state_store: ChannelStateStore::new(db.clone(), owner_address),
            ledger_info_store: LedgerStore::new(db.clone()),
            transaction_store: ChannelTransactionStore::new(db.clone()),
        }
    }
}

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
            self.ledger_info_store
                .put_ledger_info(x, &mut schema_batch)?;
        }

        self.commit(schema_batch)?;

        // Once everything is successfully persisted, update the latest in-memory ledger info.
        if let Some(x) = ledger_info_with_sigs {
            self.ledger_info_store.set_latest_ledger_info(x.clone());
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
            self.ledger_info_store
                .put_tx_info(version, &tx_info, &mut schema_batch)?;
        Ok(new_ledger_root_hash)
    }

    /// persist the batch into storage
    fn commit(&self, schema_batch: SchemaBatch) -> Result<()> {
        self.db.write_schemas(schema_batch)?;

        Ok(())
    }
}
