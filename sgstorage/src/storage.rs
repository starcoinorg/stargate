use crate::channel_state_store::ChannelStateStore;
use crate::channel_transaction_store::ChannelTransactionStore;
use crate::SgDB;
use crypto::hash::CryptoHash;
use crypto::HashValue;
use failure::prelude::*;
use lazy_static::lazy_static;
use libra_types::account_address::AccountAddress;
use libra_types::account_state_blob::AccountStateBlob;
use libra_types::crypto_proxies::LedgerInfoWithSignatures;
use libra_types::transaction::{Transaction, TransactionInfo, TransactionToCommit, Version};
use logger::prelude::*;
use metrics::OpMetrics;
use schemadb::SchemaBatch;
use std::collections::HashMap;
use std::sync::Arc;

lazy_static! {
    static ref OP_COUNTER: OpMetrics = OpMetrics::new_and_registered("storage");
}

pub struct SgStorage {
    db: Arc<SgDB>,
}

impl SgStorage {
    pub fn new(db: Arc<SgDB>) -> Self {
        Self { db }
    }
}

impl SgStorage {
    pub fn save_tx(
        &self,
        tx: &TransactionToCommit,
        version: Version,
        _ledger_info_with_sigs: Option<LedgerInfoWithSignatures>, // ignore this for now
    ) -> Result<()> {
        let mut schema_batch = SchemaBatch::default();
        // get write batch
        let _ledger_hash = self.save_tx_impl(tx, version, &mut schema_batch)?;
        // TODO: check ledger info

        // Persist
        self.commit(schema_batch)?;
        Ok(())
    }

    #[inline]
    pub fn get_channel_state_store(&self, receiver_address: AccountAddress) -> ChannelStateStore {
        ChannelStateStore::new(self.db.clone(), receiver_address)
    }

    pub fn get_channel_transaction_store(
        &self,
        receiver: AccountAddress,
    ) -> ChannelTransactionStore {
        ChannelTransactionStore::new(self.db.clone(), receiver)
    }

    fn save_tx_impl(
        &self,
        tx: &TransactionToCommit,
        version: Version,
        mut schema_batch: &mut SchemaBatch,
    ) -> Result<HashValue> {
        let (sender, receiver) = Self::get_channel_participants_from_tx(tx.transaction())?;
        Self::check_channel_state(sender, receiver, tx.account_states())?;

        let participant_address = if self.db.owner_account_address() == sender {
            receiver
        } else {
            sender
        };
        let channel_state_store = self.get_channel_state_store(participant_address);
        let state_root_hash = channel_state_store.put_channel_state_set(
            tx.account_states().clone(),
            version,
            &mut schema_batch,
        )?;
        // TODO: save events

        // TODO: save tx
        let channel_transaction_store = self.get_channel_transaction_store(participant_address);

        channel_transaction_store.put_transaction(version, tx.transaction(), &mut schema_batch)?;

        let _tx_info = TransactionInfo::new(
            tx.transaction().as_signed_user_txn()?.hash(),
            state_root_hash,
            HashValue::default(),
            tx.gas_used(),
            tx.major_status(),
        );
        // TODO: save to ledger store

        unimplemented!()
    }

    fn commit(&self, schema_batch: SchemaBatch) -> Result<()> {
        self.db.write_schemas(schema_batch)?;
        match self.db.get_approximate_sizes_cf() {
            Ok(cf_sizes) => {
                for (cf_name, size) in cf_sizes {
                    OP_COUNTER.set(&format!("cf_size_bytes_{}", cf_name), size as usize);
                }
            }
            Err(err) => warn!(
                "Failed to get approximate size of column families: {}.",
                err
            ),
        }

        Ok(())
    }

    /// helpers

    fn get_channel_participants_from_tx(
        tx: &Transaction,
    ) -> Result<(AccountAddress, AccountAddress)> {
        match tx {
            Transaction::UserTransaction(signed_tx) => match signed_tx.receiver() {
                Some(receiver) => Ok((signed_tx.sender(), receiver)),
                None => bail!("only support channel transaction"),
            },
            _ => {
                bail!("only support user transaction");
            }
        }
    }

    fn check_channel_state(
        sender: AccountAddress,
        receiver: AccountAddress,
        channel_states: &HashMap<AccountAddress, AccountStateBlob>,
    ) -> Result<()> {
        let valid = channel_states
            .keys()
            .all(|addr| *addr == sender || *addr == receiver);
        ensure!(
            valid,
            "channel_state should only contain sender or receiver data"
        );
        Ok(())
    }
}
