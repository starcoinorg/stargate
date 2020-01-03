// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::node::Node;
use anyhow::{bail, Result};
use libra_crypto::{
    ed25519::Ed25519PrivateKey,
    hash::{CryptoHash, CryptoHasher, TestOnlyHasher},
    traits::SigningKey,
};
use libra_types::account_address::AccountAddress;
use sgtypes::message::*;
use sgtypes::sg_error::SgError;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::delay_for;

#[test]
fn node_test_all() -> Result<()> {
    use crate::test_helper::*;
    use anyhow::Error;
    use futures::compat::Future01CompatExt;
    use libra_config::utils::get_available_port;
    use libra_logger::prelude::*;
    use sgchain::star_chain_client::MockChainClient;
    use std::sync::Arc;
    use tokio::runtime::Runtime;

    libra_logger::init_for_e2e_testing();
    let mut rt = Runtime::new().unwrap();
    let executor = rt.handle().clone();

    let (mock_chain_service, _handle) = MockChainClient::new();
    let client = Arc::new(mock_chain_service);
    let network_config1 = create_node_network_config(
        format!("/ip4/127.0.0.1/tcp/{}", get_available_port()),
        vec![],
    );

    let (mut node1, addr1) = gen_node(
        rt.block_on(setup_wallet(client.clone(), 10_000_000))?,
        executor.clone(),
        &network_config1,
        client.clone(),
        true,
    );
    node1.start_server(&mut rt);

    let addr1_hex = hex::encode(addr1);

    let seed = format!("{}/p2p/{}", &network_config1.listen, addr1_hex);
    let network_config2 = create_node_network_config(
        format!("/ip4/127.0.0.1/tcp/{}", get_available_port()),
        vec![seed.clone()],
    );

    let (mut node2, addr2) = gen_node(
        rt.block_on(setup_wallet(client.clone(), 10_000_000))?,
        executor.clone(),
        &network_config2,
        client.clone(),
        true,
    );
    node2.start_server(&mut rt);

    let network_config3 = create_node_network_config(
        format!("/ip4/127.0.0.1/tcp/{}", get_available_port()),
        vec![seed.clone()],
    );
    let (mut node3, addr3) = gen_node(
        rt.block_on(setup_wallet(client.clone(), 10_000_000))?,
        executor.clone(),
        &network_config3,
        client.clone(),
        true,
    );
    node3.start_server(&mut rt);

    let node1 = Arc::new(node1);
    let node2 = Arc::new(node2);
    let node3 = Arc::new(node3);
    let _node1_clone = node1.clone();
    let _node2_clone = node2.clone();
    let _node3_clone = node3.clone();

    let f = async move {
        let fund_amount = 1000000;
        let mut expected_channel_seq_number_12 = 0u64;
        let _result = node2
            .open_channel_async(addr1, fund_amount, fund_amount)
            .await
            .unwrap()
            .compat()
            .await
            .unwrap();

        expected_channel_seq_number_12 += 1;
        wait_channel_sequence_number(node1.clone(), node2.clone(), expected_channel_seq_number_12)
            .await?;

        assert_eq!(
            node2.channel_balance_async(addr1).await.unwrap(),
            fund_amount
        );

        assert_eq!(
            node1.channel_balance_async(addr2).await.unwrap(),
            fund_amount
        );

        let mut expected_channel_seq_number_23 = 0u64;

        let _result = node2
            .open_channel_async(addr3, fund_amount, fund_amount)
            .await
            .unwrap()
            .compat()
            .await
            .unwrap();
        expected_channel_seq_number_23 += 1;
        wait_channel_sequence_number(node2.clone(), node3.clone(), expected_channel_seq_number_23)
            .await?;
        assert_eq!(
            node2.channel_balance_async(addr3).await.unwrap(),
            fund_amount
        );
        assert_eq!(
            node3.channel_balance_async(addr2).await.unwrap(),
            fund_amount
        );

        let deposit_amount = 10000;
        node2
            .deposit_async(addr1, deposit_amount)
            .await
            .unwrap()
            .compat()
            .await
            .unwrap();
        expected_channel_seq_number_12 += 1;
        wait_channel_sequence_number(node1.clone(), node2.clone(), expected_channel_seq_number_12)
            .await?;

        assert_eq!(
            node2.channel_balance_async(addr1).await.unwrap(),
            fund_amount + deposit_amount
        );
        assert_eq!(
            node1.channel_balance_async(addr2).await.unwrap(),
            fund_amount
        );

        let transfer_amount = 1_000;

        let invoice = node1.add_invoice(transfer_amount).await.unwrap();
        node2
            .off_chain_pay_htlc_async(addr1, transfer_amount, invoice.r_hash, 1000)
            .await
            .unwrap()
            .compat()
            .await
            .unwrap();

        info!("sender is {}", addr2);
        expected_channel_seq_number_12 += 2;
        wait_channel_sequence_number(node1.clone(), node2.clone(), expected_channel_seq_number_12)
            .await?;

        assert_eq!(
            node2.channel_balance_async(addr1).await.unwrap(),
            fund_amount - transfer_amount + deposit_amount
        );
        assert_eq!(
            node1.channel_balance_async(addr2).await.unwrap(),
            fund_amount + transfer_amount
        );

        let offchain_txn = node2
            .off_chain_pay_async(addr1, transfer_amount)
            .await
            .unwrap()
            .compat()
            .await
            .unwrap();
        debug!("txn:{:#?}", offchain_txn);
        expected_channel_seq_number_12 += 1;
        wait_channel_sequence_number(node1.clone(), node2.clone(), expected_channel_seq_number_12)
            .await?;
        assert_eq!(
            node2.channel_balance_async(addr1).await.unwrap(),
            fund_amount - transfer_amount * 2 + deposit_amount
        );
        assert_eq!(
            node1.channel_balance_async(addr2).await.unwrap(),
            fund_amount + transfer_amount * 2
        );

        let invoice = node1.add_invoice(transfer_amount).await.unwrap();
        node3
            .off_chain_pay_htlc_async(addr1, transfer_amount, invoice.r_hash, 1000)
            .await
            .unwrap()
            .compat()
            .await
            .unwrap();

        expected_channel_seq_number_12 += 2;
        expected_channel_seq_number_23 += 2;
        wait_channel_sequence_number(node2.clone(), node1.clone(), expected_channel_seq_number_12)
            .await?;
        wait_channel_sequence_number(node3.clone(), node2.clone(), expected_channel_seq_number_23)
            .await?;

        assert_eq!(
            node3.channel_balance_async(addr2).await.unwrap(),
            fund_amount - transfer_amount
        );
        assert_eq!(
            node2.channel_balance_async(addr1).await.unwrap(),
            fund_amount - transfer_amount * 3 + deposit_amount
        );
        assert_eq!(
            node1.channel_balance_async(addr2).await.unwrap(),
            fund_amount + transfer_amount * 3
        );
        assert_eq!(
            node2.channel_balance_async(addr3).await.unwrap(),
            fund_amount + transfer_amount
        );

        let wd_amount = 10000;
        node2
            .withdraw_async(addr1, wd_amount)
            .await
            .unwrap()
            .compat()
            .await
            .unwrap();
        expected_channel_seq_number_12 += 1;
        wait_channel_sequence_number(node2.clone(), node1.clone(), expected_channel_seq_number_12)
            .await?;
        assert_eq!(
            node2.channel_balance_async(addr1).await.unwrap(),
            fund_amount - transfer_amount * 3 - wd_amount + deposit_amount
        );
        assert_eq!(
            node1.channel_balance_async(addr2).await.unwrap(),
            fund_amount + transfer_amount * 3
        );

        node1.wallet().stop().await?;
        node2.wallet().stop().await?;
        node3.wallet().stop().await?;
        node1.shutdown().unwrap();
        node2.shutdown().unwrap();
        node3.shutdown().unwrap();
        Ok::<_, Error>(())
    };
    rt.block_on(f)?;
    drop(rt);

    debug!("here");
    Ok(())
}

#[test]
fn node_test_four_hop() -> Result<()> {
    use crate::test_helper::*;
    use anyhow::Error;
    use futures::compat::Future01CompatExt;
    use libra_config::utils::get_available_port;
    use libra_logger::prelude::*;
    use sgchain::star_chain_client::MockChainClient;
    use std::sync::Arc;
    use tokio::runtime::Runtime;

    libra_logger::init_for_e2e_testing();
    let mut rt = Runtime::new().unwrap();
    let executor = rt.handle().clone();

    let (mock_chain_service, _handle) = MockChainClient::new();
    let client = Arc::new(mock_chain_service);
    let network_config1 = create_node_network_config("/ip4/127.0.0.1/tcp/5000".to_string(), vec![]);
    let (mut node1, addr1) = gen_node(
        rt.block_on(setup_wallet(client.clone(), 10_000_000))?,
        executor.clone(),
        &network_config1,
        client.clone(),
        true,
    );
    node1.start_server(&mut rt);

    let addr1_hex = hex::encode(addr1);

    let seed = format!("{}/p2p/{}", &network_config1.listen, addr1_hex);
    let network_config2 = create_node_network_config(
        format!("/ip4/127.0.0.1/tcp/{}", get_available_port()),
        vec![seed.clone()],
    );

    let (mut node2, addr2) = gen_node(
        rt.block_on(setup_wallet(client.clone(), 10_000_000))?,
        executor.clone(),
        &network_config2,
        client.clone(),
        true,
    );
    node2.start_server(&mut rt);

    let network_config3 = create_node_network_config(
        format!("/ip4/127.0.0.1/tcp/{}", get_available_port()),
        vec![seed.clone()],
    );
    let (mut node3, addr3) = gen_node(
        rt.block_on(setup_wallet(client.clone(), 10_000_000))?,
        executor.clone(),
        &network_config3,
        client.clone(),
        true,
    );
    node3.start_server(&mut rt);

    let network_config4 = create_node_network_config(
        format!("/ip4/127.0.0.1/tcp/{}", get_available_port()),
        vec![seed.clone()],
    );
    let (mut node4, addr4) = gen_node(
        rt.block_on(setup_wallet(client.clone(), 10_000_000))?,
        executor.clone(),
        &network_config4,
        client.clone(),
        true,
    );
    node4.start_server(&mut rt);

    let node1 = Arc::new(node1);
    let node2 = Arc::new(node2);
    let node3 = Arc::new(node3);
    let node4 = Arc::new(node4);
    let _node1_clone = node1.clone();
    let _node2_clone = node2.clone();
    let _node3_clone = node3.clone();
    let _node4_clone = node4.clone();

    let f = async move {
        let fund_amount = 1000000;
        let mut expected_channel_seq_number_12 = 0u64;
        let _result = node2
            .open_channel_async(addr1, fund_amount, fund_amount)
            .await
            .unwrap()
            .compat()
            .await
            .unwrap();
        expected_channel_seq_number_12 += 1;
        wait_channel_sequence_number(node1.clone(), node2.clone(), expected_channel_seq_number_12)
            .await?;
        assert_eq!(
            node2.channel_balance_async(addr1).await.unwrap(),
            fund_amount
        );
        assert_eq!(
            node1.channel_balance_async(addr2).await.unwrap(),
            fund_amount
        );

        let mut expected_channel_seq_number_23 = 0u64;
        let _result = node3
            .open_channel_async(addr2, fund_amount, fund_amount)
            .await
            .unwrap()
            .compat()
            .await
            .unwrap();
        expected_channel_seq_number_23 += 1;
        wait_channel_sequence_number(node2.clone(), node3.clone(), expected_channel_seq_number_23)
            .await?;

        assert_eq!(
            node3.channel_balance_async(addr2).await.unwrap(),
            fund_amount
        );
        assert_eq!(
            node2.channel_balance_async(addr3).await.unwrap(),
            fund_amount
        );

        let mut expected_channel_seq_number_34 = 0u64;
        let _result = node4
            .open_channel_async(addr3, fund_amount, fund_amount)
            .await
            .unwrap()
            .compat()
            .await
            .unwrap();
        expected_channel_seq_number_34 += 1;
        wait_channel_sequence_number(node3.clone(), node4.clone(), expected_channel_seq_number_34)
            .await?;

        assert_eq!(
            node4.channel_balance_async(addr3).await.unwrap(),
            fund_amount
        );
        assert_eq!(
            node3.channel_balance_async(addr4).await.unwrap(),
            fund_amount
        );

        let transfer_amount = 1_000;

        _delay(Duration::from_millis(5000)).await;

        let invoice = node1.add_invoice(transfer_amount).await.unwrap();
        node4
            .off_chain_pay_htlc_async(addr1, transfer_amount, invoice.r_hash.clone(), 1000)
            .await
            .unwrap()
            .compat()
            .await
            .unwrap();

        expected_channel_seq_number_34 += 2;
        expected_channel_seq_number_23 += 2;
        expected_channel_seq_number_12 += 2;
        wait_channel_sequence_number(node4.clone(), node3.clone(), expected_channel_seq_number_34)
            .await?;
        wait_channel_sequence_number(node3.clone(), node2.clone(), expected_channel_seq_number_23)
            .await?;
        wait_channel_sequence_number(node2.clone(), node1.clone(), expected_channel_seq_number_12)
            .await?;

        assert_eq!(
            node4.channel_balance_async(addr3).await.unwrap(),
            fund_amount - transfer_amount
        );
        assert_eq!(
            node3.channel_balance_async(addr2).await.unwrap(),
            fund_amount - transfer_amount
        );
        assert_eq!(
            node2.channel_balance_async(addr1).await.unwrap(),
            fund_amount - transfer_amount
        );
        assert_eq!(
            node1.channel_balance_async(addr2).await.unwrap(),
            fund_amount + transfer_amount
        );
        assert_eq!(
            node2.channel_balance_async(addr3).await.unwrap(),
            fund_amount + transfer_amount
        );
        assert_eq!(
            node3.channel_balance_async(addr4).await.unwrap(),
            fund_amount + transfer_amount
        );

        let offchain_txn = node3
            .off_chain_pay_async(addr2, transfer_amount * 4)
            .await
            .unwrap()
            .compat()
            .await
            .unwrap();
        debug!("txn:{:#?}", offchain_txn);

        expected_channel_seq_number_23 += 1;
        wait_channel_sequence_number(node3.clone(), node2.clone(), expected_channel_seq_number_23)
            .await?;

        assert_eq!(
            node2.channel_balance_async(addr3).await.unwrap(),
            fund_amount + transfer_amount * 5
        );
        assert_eq!(
            node3.channel_balance_async(addr2).await.unwrap(),
            fund_amount - transfer_amount * 5
        );

        let invoice = node1.add_invoice(fund_amount).await.unwrap();
        match node4
            .off_chain_pay_htlc_async(
                addr1,
                fund_amount - transfer_amount * 4,
                invoice.r_hash,
                1000,
            )
            .await
        {
            Ok(_) => assert_eq!(1, 2),
            Err(_) => assert_eq!(1, 1),
        }

        node1.wallet().stop().await?;
        node2.wallet().stop().await?;
        node3.wallet().stop().await?;
        node4.wallet().stop().await?;

        node1.shutdown().unwrap();
        node2.shutdown().unwrap();
        node3.shutdown().unwrap();
        node4.shutdown().unwrap();

        Ok::<_, Error>(())
    };
    rt.block_on(f)?;
    drop(rt);
    debug!("here");
    Ok(())
}

#[test]
fn node_test_approve() -> Result<()> {
    use crate::test_helper::*;
    use anyhow::Error;
    use futures::compat::Future01CompatExt;
    use libra_config::utils::get_available_port;
    use libra_logger::prelude::*;
    use sgchain::star_chain_client::MockChainClient;
    use std::sync::Arc;
    use tokio::runtime::Runtime;

    libra_logger::init_for_e2e_testing();
    let mut rt = Runtime::new().unwrap();
    let executor = rt.handle().clone();

    let (mock_chain_service, _handle) = MockChainClient::new();
    let client = Arc::new(mock_chain_service);
    let network_config1 = create_node_network_config(
        format!("/ip4/127.0.0.1/tcp/{}", get_available_port()),
        vec![],
    );

    let (mut node1, addr1) = gen_node(
        rt.block_on(setup_wallet(client.clone(), 10_000_000))?,
        executor.clone(),
        &network_config1,
        client.clone(),
        false,
    );
    node1.start_server(&mut rt);

    let addr1_hex = hex::encode(addr1);

    let seed = format!("{}/p2p/{}", &network_config1.listen, addr1_hex);

    let network_config2 = create_node_network_config(
        format!("/ip4/127.0.0.1/tcp/{}", get_available_port()),
        vec![seed],
    );
    let (mut node2, addr2) = gen_node(
        rt.block_on(setup_wallet(client.clone(), 10_000_000))?,
        executor.clone(),
        &network_config2,
        client.clone(),
        true,
    );
    node2.start_server(&mut rt);

    let node1 = Arc::new(node1);
    let node2 = Arc::new(node2);
    let _node1_clone = node1.clone();
    let _node2_clone = node2.clone();

    let f = async move {
        let fund_amount = 1000000;

        executor.spawn(_confirm(
            node1.clone(),
            Duration::from_millis(2000),
            addr2,
            true,
        ));

        let _result = node2
            .open_channel_async(addr1, fund_amount, fund_amount)
            .await
            .unwrap()
            .compat()
            .await
            .unwrap();
        let expected_channel_seq_number_12 = 1u64;
        wait_channel_sequence_number(node1.clone(), node2.clone(), expected_channel_seq_number_12)
            .await?;
        assert_eq!(
            node2.channel_balance_async(addr1).await.unwrap(),
            fund_amount
        );
        assert_eq!(
            node1.channel_balance_async(addr2).await.unwrap(),
            fund_amount
        );

        node1.wallet().stop().await?;
        node2.wallet().stop().await?;
        node1.shutdown().unwrap();
        node2.shutdown().unwrap();
        Ok::<_, Error>(())
    };
    rt.block_on(f)?;
    drop(rt);
    debug!("here");
    Ok(())
}

#[test]
fn node_test_reject() -> Result<()> {
    use crate::test_helper::*;
    use anyhow::Error;
    use futures::compat::Future01CompatExt;
    use libra_config::utils::get_available_port;
    use libra_logger::prelude::*;
    use sgchain::star_chain_client::MockChainClient;
    use std::sync::Arc;
    use tokio::runtime::Runtime;

    libra_logger::init_for_e2e_testing();
    let mut rt = Runtime::new().unwrap();
    let executor = rt.handle().clone();

    let (mock_chain_service, _handle) = MockChainClient::new();
    let client = Arc::new(mock_chain_service);
    let network_config1 = create_node_network_config(
        format!("/ip4/127.0.0.1/tcp/{}", get_available_port()),
        vec![],
    );

    let (mut node1, addr1) = gen_node(
        rt.block_on(setup_wallet(client.clone(), 10_000_000))?,
        executor.clone(),
        &network_config1,
        client.clone(),
        false,
    );
    node1.start_server(&mut rt);

    let addr1_hex = hex::encode(addr1);

    let seed = format!("{}/p2p/{}", &network_config1.listen, addr1_hex);

    let network_config2 = create_node_network_config(
        format!("/ip4/127.0.0.1/tcp/{}", get_available_port()),
        vec![seed],
    );
    let (mut node2, addr2) = gen_node(
        rt.block_on(setup_wallet(client.clone(), 10_000_000))?,
        executor.clone(),
        &network_config2,
        client.clone(),
        true,
    );
    node2.start_server(&mut rt);

    let node1 = Arc::new(node1);
    let node2 = Arc::new(node2);
    let _node1_clone = node1.clone();
    let _node2_clone = node2.clone();

    let f = async move {
        _delay(Duration::from_millis(1000)).await;

        let fund_amount = 1000000;

        executor.spawn(_confirm(
            node1.clone(),
            Duration::from_millis(2000),
            addr2,
            false,
        ));

        let result = node2
            .open_channel_async(addr1, fund_amount, fund_amount)
            .await
            .unwrap()
            .compat()
            .await;

        match result {
            Ok(_) => {
                assert_eq!(1, 0);
                info!("should not be here");
            }
            Err(_) => {
                assert_eq!(1, 1);
                info!("should be here");
            }
        }

        node1.wallet().stop().await?;
        node2.wallet().stop().await?;
        node1.shutdown().unwrap();
        node2.shutdown().unwrap();
        Ok::<_, Error>(())
    };
    rt.block_on(f)?;
    drop(rt);
    debug!("here");
    Ok(())
}

async fn _delay(duration: Duration) {
    delay_for(duration).await;
}

/// wait until the channel seq number between node1 and node2 is what we wanted
#[allow(dead_code)]
async fn wait_channel_sequence_number(
    node1: Arc<Node>,
    node2: Arc<Node>,
    channel_sequence_number: u64,
    //    max_timeout_in_sec: u64,
) -> Result<()> {
    let wallet1 = node1.wallet();
    let wallet2 = node2.wallet();
    let address1 = wallet1.account();
    let address2 = wallet2.account();
    let max_timeout_in_sec = 5u64;

    let mut wait_times = 0u64;
    while wallet1.channel_sequence_number(address2).await? < channel_sequence_number {
        if wait_times >= max_timeout_in_sec {
            bail!(
                "{} wait channel seq number {} for too long",
                &address1,
                channel_sequence_number
            );
        }
        delay_for(Duration::from_millis(1000)).await;
        wait_times += 1;
    }

    let mut wait_times = 0u64;
    while wallet2.channel_sequence_number(address1).await? < channel_sequence_number {
        if wait_times >= max_timeout_in_sec {
            bail!(
                "{} wait channel seq number {} for too long",
                &address2,
                channel_sequence_number
            );
        }
        delay_for(Duration::from_millis(1000)).await;
        wait_times += 1;
    }
    Ok(())
}

async fn _confirm(node: Arc<Node>, duration: Duration, addr: AccountAddress, approve: bool) {
    delay_for(duration).await;

    let mut transaction_proposal_response = node
        .get_channel_transaction_proposal_async(addr)
        .await
        .unwrap();

    node.channel_transaction_proposal_async(
        addr,
        transaction_proposal_response
            .channel_transaction
            .take()
            .expect("should have")
            .hash(),
        approve,
    )
    .await
    .unwrap();
}

#[test]
fn error_test() -> Result<()> {
    use libra_logger::prelude::*;

    ::libra_logger::try_init_for_testing();

    match _new_error() {
        Err(e) => {
            if let Some(_err) = e.downcast_ref::<SgError>() {
                info!("this is a sg error");
                assert_eq!(1, 1)
            } else {
                // fallback case
                info!("this is a common error");
                assert_eq!(1, 2)
            }
        }
        Ok(_) => info!("ok"),
    };
    Ok(())
}

fn _new_error() -> Result<()> {
    Err(SgError::new(sgtypes::sg_error::SgErrorCode::UNKNOWN, "111".to_string()).into())
}

fn _create_negotiate_message(
    sender_addr: AccountAddress,
    receiver_addr: AccountAddress,
    private_key: Ed25519PrivateKey,
) -> OpenChannelNodeNegotiateMessage {
    let resource_type = StructTag::new(sender_addr, "test".to_string(), "test".to_string(), vec![]);
    let rtx = RawNegotiateMessage::new(sender_addr, resource_type, 10, receiver_addr, 20);
    let mut hasher = TestOnlyHasher::default();
    hasher.write(&rtx.clone().into_proto_bytes().unwrap());
    let hash_value = hasher.finish();
    let sender_sign = private_key.sign_message(&hash_value);
    OpenChannelNodeNegotiateMessage::new(rtx, sender_sign, None)
}
