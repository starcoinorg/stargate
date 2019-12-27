// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::chain_watcher::{ChainWatcherHandle, TransactionWithInfo};
use crate::scripts::PackageRegistry;
use crate::tx_applier::TxApplier;
use anyhow::{bail, Result};
use coerce_rt::actor::{context::ActorContext, message::Message};
use futures::channel::mpsc;
use libra_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use libra_crypto::test_utils::KeyPair;
use libra_crypto::HashValue;
use libra_types::{
    access_path::AccessPath, account_address::AccountAddress, transaction::TransactionArgument,
    transaction::TransactionOutput, write_set::WriteOp, write_set::WriteSet,
};
use sgchain::star_chain_client::ChainClient;
use sgstorage::channel_db::ChannelDB;
use sgstorage::channel_store::ChannelStore;
use sgtypes::channel::ChannelState;
use sgtypes::channel_transaction::{ChannelOp, ChannelTransactionProposal};
use sgtypes::channel_transaction_sigs::ChannelTransactionSigs;
use sgtypes::pending_txn::PendingTransaction;
use std::collections::BTreeSet;
use std::sync::Arc;

mod channel;
mod channel_handle;
pub use channel_handle::ChannelHandle;

pub struct Channel {
    channel_address: AccountAddress,
    account_address: AccountAddress,
    // participant contains self address, use btree to preserve address order.
    participant_addresses: BTreeSet<AccountAddress>,
    channel_state: ChannelState,
    store: ChannelStore<ChannelDB>,
    keypair: Arc<KeyPair<Ed25519PrivateKey, Ed25519PublicKey>>,
    script_registry: Arc<PackageRegistry>,
    chain_client: Arc<dyn ChainClient>,
    tx_applier: TxApplier,

    // event produced by the channel
    channel_event_sender: mpsc::Sender<ChannelEvent>,
    // watch onchain channel txn of this channel
    chain_txn_watcher: ChainWatcherHandle,
}
impl Channel {
    /// load channel from storage
    pub fn load(
        channel_address: AccountAddress,
        account_address: AccountAddress,
        participant_addresses: BTreeSet<AccountAddress>,
        channel_state: ChannelState,
        db: ChannelDB,
        chain_txn_watcher: ChainWatcherHandle,
        channel_event_sender: mpsc::Sender<ChannelEvent>,
        keypair: Arc<KeyPair<Ed25519PrivateKey, Ed25519PublicKey>>,
        script_registry: Arc<PackageRegistry>,
        chain_client: Arc<dyn ChainClient>,
    ) -> Self {
        let store = ChannelStore::new(participant_addresses.clone(), db.clone())
            .unwrap_or_else(|e| panic!("create channel store should be ok, e: {}", e));
        let inner = Self {
            channel_address,
            account_address,
            participant_addresses: participant_addresses.clone(),
            channel_state,
            store: store.clone(),
            keypair: keypair.clone(),
            script_registry: script_registry.clone(),
            chain_client: chain_client.clone(),
            tx_applier: TxApplier::new(store.clone()),
            channel_event_sender,
            chain_txn_watcher,
        };
        inner
    }

    pub async fn start(self, mut context: ActorContext) -> ChannelHandle {
        let channel_address = self.channel_address;
        let account_address = self.account_address;
        let participant_addresses = self.participant_addresses.clone();

        let actor_ref = context
            .new_actor(self)
            .await
            .expect("actor context is closed");

        ChannelHandle::new(
            channel_address,
            account_address,
            participant_addresses,
            actor_ref,
        )
    }
}

pub(crate) struct Execute {
    pub channel_op: ChannelOp,
    pub args: Vec<TransactionArgument>,
}
impl Message for Execute {
    type Result = Result<(
        ChannelTransactionProposal,
        ChannelTransactionSigs,
        TransactionOutput,
    )>;
}
pub(crate) struct CollectProposalWithSigs {
    pub proposal: ChannelTransactionProposal,
    /// the sigs maybe proposer's, or other participant's.
    pub sigs: ChannelTransactionSigs,
}
impl Message for CollectProposalWithSigs {
    type Result = Result<Option<ChannelTransactionSigs>>;
}
pub(crate) struct GrantProposal {
    pub channel_txn_id: HashValue,
    pub grant: bool,
}
impl Message for GrantProposal {
    type Result = Result<Option<ChannelTransactionSigs>>;
}
pub(crate) struct CancelPendingTxn {
    pub channel_txn_id: HashValue,
}
impl Message for CancelPendingTxn {
    type Result = Result<()>;
}
pub(crate) struct ApplyPendingTxn {
    pub proposal: ChannelTransactionProposal,
}
/// return a (sender, seq_number) txn to watch if travel.
impl Message for ApplyPendingTxn {
    type Result = Result<Option<(AccountAddress, u64)>>;
}
pub(crate) struct ApplyTravelTxn {
    pub channel_txn: TransactionWithInfo,
}
impl Message for ApplyTravelTxn {
    type Result = Result<u64>;
}

pub(crate) struct ForceTravel;
impl Message for ForceTravel {
    type Result = Result<(AccountAddress, u64)>;
}
pub(crate) struct GetPendingTxn;
impl Message for GetPendingTxn {
    type Result = Option<PendingTransaction>;
}

pub(crate) struct AccessingResource {
    pub path: AccessPath,
}
impl Message for AccessingResource {
    type Result = Result<Option<Vec<u8>>>;
}

pub enum ChannelEvent {
    Stopped { channel_address: AccountAddress },
}

pub(crate) fn access_local<'a>(
    latest_write_set: &'a WriteSet,
    channel_state: &'a ChannelState,
    access_path: &AccessPath,
) -> Result<Option<&'a [u8]>> {
    let data = match latest_write_set.get(access_path) {
        Some(op) => match op {
            WriteOp::Value(value) => Some(value),
            WriteOp::Deletion => None,
        },
        None => {
            if channel_state.address() != &access_path.address {
                bail!("Unexpected access_path: {}", access_path)
            } else {
                channel_state.get(&access_path.path)
            }
        }
    };
    Ok(data.map(|d| d.as_slice()))
}
