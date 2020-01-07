// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

mod common;
mod mock_chain_test_helper;
mod rpc_chain_test_helper;

#[macro_use]
extern crate rusty_fork;
use anyhow::Result;
use coerce_rt::actor::context::{ActorContext, ActorStatus};
use libra_crypto::HashValue;
use libra_logger::prelude::*;
use libra_types::{
    access_path::DataPath,
    account_address::AccountAddress,
    channel::ChannelResource,
    libra_resource::{make_resource, LibraResource},
    transaction::{Transaction, TransactionPayload},
};
use rpc_chain_test_helper::run_with_rpc_client;
use sgwallet::{
    chain_watcher::{ChainWatcher, Interest, TransactionWithInfo},
    wallet::WalletHandle,
};
use std::{sync::Arc, time::Duration};

rusty_fork_test! {
#[test]
fn run_test_channel_lock_and_then_resolve() {
    if let Err(e) = run_with_rpc_client(|chain_client| {
        common::with_wallet(chain_client.clone(), |rt, sender, receiver| {
            rt.block_on(test_channel_lock_and_resolve(sender, receiver))
        })
    }) {
        panic!("error, {}", e);
    }
}

#[test]
fn run_test_channel_lock_and_then_chanllenge() {
    if let Err(e) = run_with_rpc_client(|chain_client| {
        common::with_wallet(chain_client, |rt, sender, receiver| {
            rt.block_on(test_channel_lock_and_challenge(sender, receiver))
        })
    }) {
        panic!("error, {}", e);
    }
}

#[test]
fn run_test_channel_lock_and_then_timeout() {
    if let Err(e) = run_with_rpc_client(|chain_client| {
        common::with_wallet(chain_client, |rt, sender, receiver| {
            rt.block_on(test_channel_lock_and_timeout(sender, receiver))
        })
    }) {
        panic!("error, {}", e);
    }
}
}

async fn test_channel_lock_and_resolve(
    sender: Arc<WalletHandle>,
    receiver: Arc<WalletHandle>,
) -> Result<()> {
    let _sender_init_balance = sender.balance()?;
    let _receiver_init_balance = receiver.balance()?;
    let _gas = common::open_channel(sender.clone(), receiver.clone(), 10000, 10000).await?;
    assert_eq!(1, sender.channel_sequence_number(receiver.account()).await?);
    assert_eq!(1, receiver.channel_sequence_number(sender.account()).await?);

    let _ = common::transfer(sender.clone(), receiver.clone(), 300).await?;
    assert_eq!(2, sender.channel_sequence_number(receiver.account()).await?);
    assert_eq!(2, receiver.channel_sequence_number(sender.account()).await?);

    let preimage = HashValue::random();
    let lock = preimage.to_vec();
    let _request = sender
        .send_payment(receiver.account(), 500, lock, 10)
        .await?;
    let _gas = sender.force_travel_txn(receiver.account()).await?;
    assert_eq!(3, sender.channel_sequence_number(receiver.account()).await?);

    let sender_channel_handle = sender.channel_handle(receiver.account()).await?;
    let receiver_channel_handle = receiver.channel_handle(sender.account()).await?;

    let sender_channel_handle_clone = sender_channel_handle.clone();
    let receiver_channel_handle_clone = receiver_channel_handle.clone();

    tokio::task::spawn(async move {
        loop {
            tokio::time::delay_for(Duration::from_secs(2)).await;
            let sender_channel_resource = sender_channel_handle
                .get_channel_resource::<ChannelResource>(DataPath::onchain_resource_path(
                    ChannelResource::struct_tag(),
                ))
                .await
                .unwrap();
            let receiver_channel_resource = receiver_channel_handle
                .get_channel_resource::<ChannelResource>(DataPath::onchain_resource_path(
                    ChannelResource::struct_tag(),
                ))
                .await
                .unwrap();
            info!("sender channel_resource: {:?}", sender_channel_resource);
            info!("receiver channel_resource: {:?}", receiver_channel_resource);
        }
    });

    let chain_watcher = ChainWatcher::new(sender.get_chain_client(), 0, 10);
    let actor_context = ActorContext::new();
    let chain_watcher_handle = chain_watcher.start(actor_context.clone()).await?;

    let channel_address = sender_channel_handle_clone.channel_address().clone();

    let channel_txn_receiver = chain_watcher_handle
        .add_interest_oneshot(channel_txn_interest_oneshot(channel_address, 3))
        .await?;
    let txn_with_info: TransactionWithInfo = channel_txn_receiver.await?;
    let _resolve_txn_version = txn_with_info.version;
    // delay 1s to let channel handle events
    tokio::time::delay_for(Duration::from_secs(1)).await;

    let sender_channel_resource = sender_channel_handle_clone
        .get_channel_resource::<ChannelResource>(DataPath::onchain_resource_path(
            ChannelResource::struct_tag(),
        ))
        .await?
        .unwrap();

    let receiver_channel_resource = receiver_channel_handle_clone
        .get_channel_resource::<ChannelResource>(DataPath::onchain_resource_path(
            ChannelResource::struct_tag(),
        ))
        .await?
        .unwrap();
    assert!(sender_channel_resource.opened());
    assert!(receiver_channel_resource.opened());
    Ok(())
}

async fn test_channel_lock_and_challenge(
    sender: Arc<WalletHandle>,
    receiver: Arc<WalletHandle>,
) -> Result<()> {
    let _sender_init_balance = sender.balance()?;
    let _receiver_init_balance = receiver.balance()?;
    let _gas = common::open_channel(sender.clone(), receiver.clone(), 10000, 10000).await?;
    assert_eq!(1, sender.channel_sequence_number(receiver.account()).await?);
    assert_eq!(1, receiver.channel_sequence_number(sender.account()).await?);

    let _ = common::transfer(sender.clone(), receiver.clone(), 300).await?;
    assert_eq!(2, sender.channel_sequence_number(receiver.account()).await?);
    assert_eq!(2, receiver.channel_sequence_number(sender.account()).await?);

    let preimage = HashValue::random();
    let lock = preimage.to_vec();
    let request = sender
        .send_payment(receiver.account(), 500, lock, 10)
        .await?;

    // make receiver apply
    let resp = receiver.verify_txn(sender.account(), &request).await?;
    assert!(resp.is_some());
    let resp = resp.unwrap();

    receiver.apply_txn(sender.account(), &resp).await?;
    assert_eq!(3, receiver.channel_sequence_number(sender.account()).await?);

    // but sender didn't receive the signature, so he solo
    sender.force_travel_txn(receiver.account()).await?;
    assert_eq!(3, sender.channel_sequence_number(receiver.account()).await?);

    let sender_channel_handle = sender.channel_handle(receiver.account()).await?;
    let receiver_channel_handle = receiver.channel_handle(sender.account()).await?;
    let chain_watcher = ChainWatcher::new(sender.get_chain_client(), 0, 10);
    let actor_context = ActorContext::new();
    let chain_watcher_handle = chain_watcher.start(actor_context.clone()).await?;

    let channel_address = sender_channel_handle.channel_address().clone();
    let channel_txn_receiver = chain_watcher_handle
        .add_interest_oneshot(channel_txn_interest_oneshot(channel_address, 3))
        .await?;
    let txn_with_info: TransactionWithInfo = channel_txn_receiver.await?;
    let channel_state = sender
        .get_chain_client()
        .get_account_state(channel_address, Some(txn_with_info.version))?;
    let channel_resource = channel_state
        .get(&DataPath::onchain_resource_path(ChannelResource::struct_tag()).to_vec())
        .map(|b| make_resource::<ChannelResource>(&b))
        .transpose()?
        .expect("channel resource should exists");
    assert!(
        channel_resource.closed(),
        "channel should be closed, locked: {}",
        channel_resource.locked()
    );
    // delay 1s to let channel handle events
    tokio::time::delay_for(Duration::from_secs(1)).await;
    if let Ok(s) = sender_channel_handle.channel_ref().status().await {
        assert!(s == ActorStatus::Stopping || s == ActorStatus::Stopped)
    }
    if let Ok(s) = receiver_channel_handle.channel_ref().status().await {
        assert!(s == ActorStatus::Stopping || s == ActorStatus::Stopped)
    }
    Ok(())
}

async fn test_channel_lock_and_timeout(
    sender: Arc<WalletHandle>,
    receiver: Arc<WalletHandle>,
) -> Result<()> {
    let _sender_init_balance = sender.balance()?;
    let _receiver_init_balance = receiver.balance()?;
    let _gas = common::open_channel(sender.clone(), receiver.clone(), 10000, 10000).await?;
    assert_eq!(1, sender.channel_sequence_number(receiver.account()).await?);
    assert_eq!(1, receiver.channel_sequence_number(sender.account()).await?);

    let _ = common::transfer(sender.clone(), receiver.clone(), 300).await?;
    assert_eq!(2, sender.channel_sequence_number(receiver.account()).await?);
    assert_eq!(2, receiver.channel_sequence_number(sender.account()).await?);

    let preimage = HashValue::random();
    let lock = preimage.to_vec();
    let _request = sender
        .send_payment(receiver.account(), 500, lock, 10)
        .await?;

    receiver.stop().await?;

    // but sender didn't receive the signature, so he solo
    sender.force_travel_txn(receiver.account()).await?;
    assert_eq!(3, sender.channel_sequence_number(receiver.account()).await?);

    let sender_channel_handle = sender.channel_handle(receiver.account()).await?;
    let chain_watcher = ChainWatcher::new(sender.get_chain_client(), 0, 10);
    let actor_context = ActorContext::new();
    let chain_watcher_handle = chain_watcher.start(actor_context.clone()).await?;
    // wait timeout and close channel
    let channel_address = sender_channel_handle.channel_address().clone();
    let channel_txn_receiver = chain_watcher_handle
        .add_interest_oneshot(channel_txn_interest_oneshot(channel_address, 3))
        .await?;
    let txn_with_info: TransactionWithInfo = channel_txn_receiver.await?;
    let channel_state = sender
        .get_chain_client()
        .get_account_state(channel_address, Some(txn_with_info.version))?;
    let channel_resource = channel_state
        .get(&DataPath::onchain_resource_path(ChannelResource::struct_tag()).to_vec())
        .map(|b| make_resource::<ChannelResource>(&b))
        .transpose()?
        .expect("channel resource should exists");
    assert!(
        channel_resource.closed(),
        "channel should be closed, locked: {}",
        channel_resource.locked()
    );

    // delay 1s to let channel handle events
    tokio::time::delay_for(Duration::from_secs(1)).await;
    if let Ok(s) = sender_channel_handle.channel_ref().status().await {
        assert!(s == ActorStatus::Stopping || s == ActorStatus::Stopped)
    }

    // FIXME: check receiver restart ok
    Ok(())
}

fn channel_txn_interest_oneshot(
    channel_address: AccountAddress,
    channel_sequence_number: u64,
) -> Interest {
    Box::new(move |txn| match &txn.txn {
        Transaction::UserTransaction(s) => {
            if let TransactionPayload::Channel(cp) = s.payload() {
                cp.channel_address() == channel_address
                    && cp.channel_sequence_number() == channel_sequence_number
            } else {
                false
            }
        }
        _ => false,
    })
}
