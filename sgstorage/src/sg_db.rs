use crate::channel_db::ChannelDB;
use crate::channel_state_store::ChannelStateStore;
use crate::channel_store::ChannelStore;
use crate::channel_transaction_store::ChannelTransactionStore;
use crate::storage::SgStorage;
use failure::prelude::*;
use lazy_static::lazy_static;
use libra_types::account_address::AccountAddress;
use libra_types::account_state_blob::AccountStateBlob;
use libra_types::crypto_proxies::LedgerInfoWithSignatures;
use libra_types::transaction::{Transaction, TransactionToCommit, Version};
use libradb::schema::{JELLYFISH_MERKLE_NODE_CF_NAME, STALE_NODE_INDEX_CF_NAME};
use logger::prelude::*;
use metrics::OpMetrics;
use schemadb::{ColumnFamilyOptions, DEFAULT_CF_NAME};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

lazy_static! {
    static ref OP_COUNTER: OpMetrics = OpMetrics::new_and_registered("storage");
}

pub struct SgDB {
    db: Arc<SgStorage>,
    owner_address: AccountAddress,
}

impl SgDB {
    pub fn open<P: AsRef<Path>>(owner: AccountAddress, path: P) -> Self {
        let cfs = [
            (DEFAULT_CF_NAME, ColumnFamilyOptions::default()),
            (
                JELLYFISH_MERKLE_NODE_CF_NAME,
                ColumnFamilyOptions::default(),
            ),
            (STALE_NODE_INDEX_CF_NAME, ColumnFamilyOptions::default()),
        ]
        .iter()
        .cloned()
        .collect();

        let path = path.as_ref().join("stargatedb");
        let instant = Instant::now();
        let storage = SgStorage::open(owner, &path, cfs)
            .unwrap_or_else(|e| panic!("SG DB open failed: {:?}", e));

        info!(
            "Opened SG DB at {:?} in {} ms",
            path,
            instant.elapsed().as_millis()
        );

        Self {
            db: Arc::new(storage),
            owner_address: owner,
        }
    }
}

impl SgDB {
    #[inline]
    pub fn get_channel_db(&self, participant_address: AccountAddress) -> ChannelDB {
        ChannelDB::new(participant_address, self.db.clone())
    }

    #[inline]
    pub fn get_channel_state_store(
        &self,
        participant_address: AccountAddress,
    ) -> ChannelStateStore<ChannelDB> {
        let channel_db = ChannelDB::new(participant_address, self.db.clone());
        ChannelStateStore::new(Arc::new(channel_db), self.owner_address)
    }

    pub fn get_channel_transaction_store(
        &self,
        participant_address: AccountAddress,
    ) -> ChannelTransactionStore<ChannelDB> {
        let channel_db = ChannelDB::new(participant_address, self.db.clone());
        ChannelTransactionStore::new(Arc::new(channel_db))
    }

    pub fn save_tx(
        &self,
        tx: &TransactionToCommit,
        version: Version,
        _ledger_info_with_sigs: &Option<LedgerInfoWithSignatures>, // ignore this for now
    ) -> Result<()> {
        let (sender, receiver) = Self::get_channel_participants_from_tx(tx.transaction())?;
        Self::check_channel_state(sender, receiver, tx.account_states())?;

        let participant_address = if self.owner_address == sender {
            receiver
        } else {
            sender
        };

        let channel_store = ChannelStore::new(
            Arc::new(ChannelDB::new(participant_address, self.db.clone())),
            self.owner_address,
        );

        channel_store.save_tx(tx, version, _ledger_info_with_sigs)?;

        // do metrics
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
