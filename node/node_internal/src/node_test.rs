// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use failure::prelude::*;

use crate::node::Node;
use libra_crypto::{
    ed25519::Ed25519PrivateKey,
    hash::{CryptoHash, CryptoHasher, TestOnlyHasher},
    traits::SigningKey,
};
use libra_types::account_address::AccountAddress;
use sgtypes::message::*;
use sgtypes::sg_error::SgError;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn node_test() -> Result<()> {
    use crate::test_helper::*;
    use futures::compat::Future01CompatExt;
    use libra_logger::prelude::*;
    use sgchain::star_chain_client::MockChainClient;
    use std::sync::Arc;
    use tokio::runtime::Runtime;

    libra_logger::init_for_e2e_testing();
    let rt = Runtime::new().unwrap();
    let executor = rt.executor();

    let (mock_chain_service, _handle) = MockChainClient::new();
    let client = Arc::new(mock_chain_service);
    let network_config1 = create_node_network_config("/ip4/127.0.0.1/tcp/5000".to_string(), vec![]);
    let (mut node1, addr1) = gen_node(executor.clone(), &network_config1, client.clone(), true);
    node1.start_server();

    let addr1_hex = hex::encode(addr1);

    let seed = format!(
        "{}/p2p/{}",
        "/ip4/127.0.0.1/tcp/5000".to_string(),
        addr1_hex
    );
    let network_config2 =
        create_node_network_config("/ip4/127.0.0.1/tcp/5001".to_string(), vec![seed]);
    let (mut node2, addr2) = gen_node(executor.clone(), &network_config2, client.clone(), true);
    node2.start_server();

    let f = async move {
        _delay(Duration::from_millis(1000)).await;

        let fund_amount = 1000000;
        let _result = node2
            .open_channel_async(addr1, fund_amount, fund_amount)
            .await
            .unwrap()
            .compat()
            .await
            .unwrap();

        _delay(Duration::from_millis(500)).await;
        assert_eq!(
            node2.channel_balance_async(addr1).await.unwrap(),
            fund_amount
        );
        assert_eq!(
            node1.channel_balance_async(addr2).await.unwrap(),
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

        // NOTICE: delay longer, give dual some time to save into local store.
        _delay(Duration::from_millis(500)).await;
        assert_eq!(
            node2.channel_balance_async(addr1).await.unwrap(),
            fund_amount + deposit_amount
        );
        assert_eq!(
            node1.channel_balance_async(addr2).await.unwrap(),
            fund_amount
        );

        let transfer_amount = 1_000;

        let invoice = node1.add_invoice().await.unwrap();
        node2
            .off_chain_pay_htlc_async(addr1, transfer_amount, invoice.r_hash, 1000)
            .await
            .unwrap()
            .compat()
            .await
            .unwrap();

        info!("sender is {}", addr2);
        _delay(Duration::from_millis(500)).await;
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

        _delay(Duration::from_millis(500)).await;
        assert_eq!(
            node2.channel_balance_async(addr1).await.unwrap(),
            fund_amount - transfer_amount * 2 + deposit_amount
        );
        assert_eq!(
            node1.channel_balance_async(addr2).await.unwrap(),
            fund_amount + transfer_amount * 2
        );

        let wd_amount = 10000;
        node2
            .withdraw_async(addr1, wd_amount)
            .await
            .unwrap()
            .compat()
            .await
            .unwrap();

        _delay(Duration::from_millis(500)).await;
        assert_eq!(
            node2.channel_balance_async(addr1).await.unwrap(),
            fund_amount - transfer_amount * 2 - wd_amount + deposit_amount
        );
        assert_eq!(
            node1.channel_balance_async(addr2).await.unwrap(),
            fund_amount + transfer_amount * 2
        );

        node1.wallet().stop().await?;
        node2.wallet().stop().await?;
        node1.shutdown().unwrap();
        node2.shutdown().unwrap();
        Ok::<_, Error>(())
    };
    rt.block_on(f)?;
    rt.shutdown_on_idle();

    debug!("here");
    Ok(())
}

#[test]
fn node_test_approve() -> Result<()> {
    use crate::test_helper::*;
    use futures::compat::Future01CompatExt;
    use libra_logger::prelude::*;
    use sgchain::star_chain_client::MockChainClient;
    use std::sync::Arc;
    use tokio::runtime::Runtime;

    libra_logger::init_for_e2e_testing();
    let rt = Runtime::new().unwrap();
    let executor = rt.executor();

    let (mock_chain_service, _handle) = MockChainClient::new();
    let client = Arc::new(mock_chain_service);
    let network_config1 = create_node_network_config("/ip4/127.0.0.1/tcp/5000".to_string(), vec![]);
    let (mut node1, addr1) = gen_node(executor.clone(), &network_config1, client.clone(), false);
    node1.start_server();

    let addr1_hex = hex::encode(addr1);

    let seed = format!(
        "{}/p2p/{}",
        "/ip4/127.0.0.1/tcp/5000".to_string(),
        addr1_hex
    );
    let network_config2 =
        create_node_network_config("/ip4/127.0.0.1/tcp/5001".to_string(), vec![seed]);
    let (mut node2, addr2) = gen_node(executor.clone(), &network_config2, client.clone(), true);
    node2.start_server();

    let node1 = Arc::new(node1);

    let f = async move {
        _delay(Duration::from_millis(1000)).await;

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

        _delay(Duration::from_millis(500)).await;
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
    rt.shutdown_on_idle();

    debug!("here");
    Ok(())
}

#[test]
fn node_test_reject() -> Result<()> {
    use crate::test_helper::*;
    use futures::compat::Future01CompatExt;
    use libra_logger::prelude::*;
    use sgchain::star_chain_client::MockChainClient;
    use std::sync::Arc;
    use tokio::runtime::Runtime;

    libra_logger::init_for_e2e_testing();
    let rt = Runtime::new().unwrap();
    let executor = rt.executor();

    let (mock_chain_service, _handle) = MockChainClient::new();
    let client = Arc::new(mock_chain_service);
    let network_config1 = create_node_network_config("/ip4/127.0.0.1/tcp/5000".to_string(), vec![]);
    let (mut node1, addr1) = gen_node(executor.clone(), &network_config1, client.clone(), false);
    node1.start_server();

    let addr1_hex = hex::encode(addr1);

    let seed = format!(
        "{}/p2p/{}",
        "/ip4/127.0.0.1/tcp/5000".to_string(),
        addr1_hex
    );
    let network_config2 =
        create_node_network_config("/ip4/127.0.0.1/tcp/5001".to_string(), vec![seed]);
    let (mut node2, addr2) = gen_node(executor.clone(), &network_config2, client.clone(), true);
    node2.start_server();

    let node1 = Arc::new(node1);

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
    rt.shutdown_on_idle();

    debug!("here");
    Ok(())
}

async fn _delay(duration: Duration) {
    let timeout_time = Instant::now() + duration;
    tokio::timer::delay(timeout_time).await;
}

async fn _confirm(node: Arc<Node>, duration: Duration, addr: AccountAddress, approve: bool) {
    let timeout_time = Instant::now() + duration;
    tokio::timer::delay(timeout_time).await;

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
