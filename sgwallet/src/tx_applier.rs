// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use anyhow::{ensure, Result};
use itertools::Itertools;
use libra_crypto::hash::{CryptoHash, EventAccumulatorHasher, HashValue};
use libra_logger::prelude::*;

use libra_types::proof::accumulator::InMemoryAccumulator;
use sgstorage::{channel_db::ChannelDB, channel_store::ChannelStore};
use sgtypes::{
    channel_transaction_info::ChannelTransactionInfo,
    channel_transaction_to_commit::ChannelTransactionToCommit, hash::*, ledger_info::LedgerInfo,
    write_set_item::WriteSetItem,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub struct AppliedTrees {
    epoch: u64,
    tx_accumulator: InMemoryAccumulator<ChannelTransactionAccumulatorHasher>,
}

#[derive(Debug)]
pub struct TxApplier {
    applied_trees: AppliedTrees,
    store: ChannelStore<ChannelDB>,
}

impl TxApplier {
    pub fn new(store: ChannelStore<ChannelDB>) -> Self {
        let startup_info = store
            .get_startup_info()
            .expect("Fail to read startup info from storage");

        let (frozen_subtrees_in_accumulator, num_leaves_in_accumulator, epoch) = match startup_info
        {
            Some(info) => {
                info!("Startup info read from DB: {:?}.", info);
                let ledger_info = info.ledger_info;

                (
                    info.ledger_frozen_subtree_hashes,
                    info.latest_version + 1,
                    ledger_info.epoch(),
                )
            }
            None => {
                info!("Startup info is empty. Will start from GENESIS.");
                (vec![], 0, 0)
            }
        };
        let applied_trees = AppliedTrees {
            epoch,
            tx_accumulator: InMemoryAccumulator::new(
                frozen_subtrees_in_accumulator,
                num_leaves_in_accumulator,
            )
            .expect("the startup info read from storage should be valid"),
        };

        Self {
            applied_trees,
            store,
        }
    }

    pub fn apply(&mut self, tx_to_commit: ChannelTransactionToCommit) -> Result<()> {
        let ChannelTransactionToCommit {
            signed_channel_txn,
            write_set,
            events,
            major_status,
            gas_used,
            ..
        } = tx_to_commit;
        let channel_seq_number = signed_channel_txn.channel_sequence_number();
        ensure!(
            channel_seq_number == self.applied_trees.tx_accumulator.num_leaves(),
            "tx channel seq number mismatched"
        );

        let _event_tree = InMemoryAccumulator::<EventAccumulatorHasher>::default()
            .append(events.iter().map(CryptoHash::hash).collect_vec().as_slice());

        let write_set_tree = InMemoryAccumulator::<WriteSetAccumulatorHasher>::default().append(
            write_set
                .iter()
                .map(|(ap, wp)| WriteSetItem(ap.clone(), wp.clone()).hash())
                .collect_vec()
                .as_slice(),
        );
        let travel = signed_channel_txn.travel();
        let txn_info = ChannelTransactionInfo::new(
            signed_channel_txn.hash(),
            write_set_tree.root_hash(),
            HashValue::default(), // TODO: event_tree.root_hash(),
            major_status,
            travel,
            gas_used,
        );

        let new_txn_accumulator = self
            .applied_trees
            .tx_accumulator
            .append(vec![txn_info.hash()].as_slice());

        debug_assert!(new_txn_accumulator.num_leaves() == channel_seq_number + 1);
        let new_epoch = if travel {
            self.applied_trees.epoch + 1
        } else {
            self.applied_trees.epoch
        };

        let ledger_info = LedgerInfo::new(
            channel_seq_number,
            new_txn_accumulator.root_hash(),
            new_epoch,
            get_current_timestamp().as_micros() as u64,
        );

        let txn_to_commit = ChannelTransactionToCommit {
            signed_channel_txn,
            write_set,
            events,
            major_status,
            gas_used,
        };

        self.store
            .save_tx(txn_to_commit, channel_seq_number, &Some(ledger_info), true)?;

        self.applied_trees = AppliedTrees {
            epoch: new_epoch,
            tx_accumulator: new_txn_accumulator,
        };

        Ok(())
    }
}

// Using current_timestamp
// because it's a bit hard to generate incremental timestamps
fn get_current_timestamp() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Timestamp generated is before the UNIX_EPOCH!")
}
