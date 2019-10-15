pub mod channel_state_store;
pub mod schema;
#[cfg(test)]
mod tests;
pub mod types;
use libra_types::account_address::AccountAddress;
use libra_types::transaction::TransactionToCommit;
use logger::prelude::*;
use schemadb::{ColumnFamilyOptions, DB, DEFAULT_CF_NAME};
use std::path::Path;
use std::time::Instant;

pub struct SgDB {
    db: DB,
    owner_account_address: AccountAddress,
}

impl SgDB {
    pub fn new<P: AsRef<Path> + Clone>(
        db_root_path: P,
        owner_account_address: AccountAddress,
    ) -> Self {
        let cfs = [
            (DEFAULT_CF_NAME, ColumnFamilyOptions::default()),
            (
                schema::SCOPED_JELLYFISH_MERKLE_NODE_CF_NAME,
                ColumnFamilyOptions::default(),
            ),
            (
                schema::SCOPED_STALE_NODE_INDEX_CF_NAME,
                ColumnFamilyOptions::default(),
            ),
        ]
        .iter()
        .cloned()
        .collect();

        let path = db_root_path.as_ref().join("stargatedb");
        let instant = Instant::now();
        let db =
            DB::open(path.clone(), cfs).unwrap_or_else(|e| panic!("SG DB open failed: {:?}", e));

        info!(
            "Opened SG DB at {:?} in {} ms",
            path,
            instant.elapsed().as_millis()
        );
        Self {
            db,
            owner_account_address,
        }
    }

    pub fn owner_account_address(&self) -> AccountAddress {
        self.owner_account_address
    }

    pub fn save_transaction(&self, _tx: &TransactionToCommit) {
        //        let signed_txn = tx.signed_txn();
        //        let txn_payload = signed_txn.raw_txn().payload();
        //        if txn_payload.is_channel_script() || txn_payload.is_channel_write_set() {
        //            //
        //        } else {
        //            // start a new epoch
        //        }
    }
}

impl AsMut<DB> for SgDB {
    fn as_mut(&mut self) -> &mut DB {
        &mut self.db
    }
}
impl AsRef<DB> for SgDB {
    fn as_ref(&self) -> &DB {
        &self.db
    }
}

impl core::ops::Deref for SgDB {
    type Target = DB;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl core::ops::DerefMut for SgDB {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut()
    }
}
