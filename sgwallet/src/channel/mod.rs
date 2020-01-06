// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{chain_watcher::ChainWatcherHandle, scripts::PackageRegistry, tx_applier::TxApplier};
use anyhow::{bail, Result};
use coerce_rt::actor::{context::ActorContext, message::Message, ActorRef};

use crate::{channel::channel_stm::ChannelStm, wallet::Wallet};
pub use channel_handle::ChannelHandle;
use libra_crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
    test_utils::KeyPair,
    HashValue,
};
use libra_types::{
    access_path::AccessPath,
    account_address::AccountAddress,
    contract_event::ContractEvent,
    transaction::{Transaction, TransactionArgument, TransactionInfo, TransactionOutput},
    write_set::{WriteOp, WriteSet},
};
use sgchain::star_chain_client::ChainClient;
use sgstorage::{channel_db::ChannelDB, channel_store::ChannelStore};
use sgtypes::{
    channel::ChannelState,
    channel_transaction::{ChannelOp, ChannelTransactionProposal},
    channel_transaction_sigs::ChannelTransactionSigs,
    pending_txn::PendingTransaction,
};
use std::{collections::BTreeSet, sync::Arc};

mod channel;
mod channel_event_stream;
mod channel_handle;
mod channel_stm;

pub struct Channel {
    store: ChannelStore<ChannelDB>,
    chain_client: Arc<dyn ChainClient>,
    tx_applier: TxApplier,

    // event produced by the channel
    channel_event_sender: ActorRef<Wallet>,

    // watch onchain channel txn of this channel
    chain_txn_watcher: ChainWatcherHandle,
    stm: ChannelStm,
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
        supervisor_ref: ActorRef<Wallet>,
        keypair: Arc<KeyPair<Ed25519PrivateKey, Ed25519PublicKey>>,
        script_registry: Arc<PackageRegistry>,
        chain_client: Arc<dyn ChainClient>,
    ) -> Self {
        let store = ChannelStore::new(participant_addresses.clone(), db.clone())
            .unwrap_or_else(|e| panic!("create channel store should be ok, e: {}", e));
        let stm = ChannelStm::new(
            channel_address.clone(),
            account_address.clone(),
            participant_addresses.clone(),
            store.get_participant_keys(),
            channel_state.clone(),
            store.get_latest_witness().unwrap_or_default(),
            keypair.clone(),
            script_registry.clone(),
            chain_client.clone(),
        );
        let inner = Self {
            store: store.clone(),
            chain_client: chain_client.clone(),
            tx_applier: TxApplier::new(store.clone()),
            channel_event_sender: supervisor_ref,
            chain_txn_watcher,
            stm,
        };
        inner
    }

    pub async fn start(self, mut context: ActorContext) -> ChannelHandle {
        let channel_address = self.channel_address().clone();
        let account_address = self.account_address().clone();
        let participant_addresses = self.participant_addresses().clone();

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

    pub fn channel_address(&self) -> &AccountAddress {
        &self.stm.channel_address
    }
    pub fn account_address(&self) -> &AccountAddress {
        &self.stm.account_address
    }
    pub fn participant_addresses(&self) -> &BTreeSet<AccountAddress> {
        &self.stm.participant_addresses
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
}
impl Message for GrantProposal {
    type Result = Result<ChannelTransactionSigs>;
}
pub(crate) struct CancelPendingTxn {
    pub channel_txn_id: HashValue,
}
impl Message for CancelPendingTxn {
    type Result = Result<()>;
}
pub(crate) struct ApplyPendingTxn;
/// return a (sender, seq_number) txn to watch if travel.
impl Message for ApplyPendingTxn {
    type Result = Result<Option<(AccountAddress, u64)>>;
}

pub(crate) struct ApplySoloTxn {
    pub txn: Transaction,
    pub txn_info: TransactionInfo,
    pub version: u64,
    pub events: Vec<ContractEvent>,
}

impl Message for ApplySoloTxn {
    type Result = Result<u64>;
}

pub(crate) struct ApplyCoSignedTxn {
    pub txn: Transaction,
    pub txn_info: TransactionInfo,
    pub version: u64,
    pub events: Vec<ContractEvent>,
}
impl Message for ApplyCoSignedTxn {
    type Result = Result<u64>;
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
