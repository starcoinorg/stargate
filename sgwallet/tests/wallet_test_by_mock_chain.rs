// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::wallet_test_helper::{
    deploy_custom_module_and_script, test_deploy_custom_module, test_wallet_async,
};
use anyhow::Result;
use libra_types::transaction::TransactionArgument;
use sgchain::star_chain_client::{ChainClient, MockChainClient};
use sgtypes::script_package::ChannelScriptPackage;
use std::sync::Arc;
use std::time::Duration;
mod common;
pub mod wallet_test_helper;

#[test]
fn test_wallet_with_mock_client() {
    if let Err(e) = run_with_mock_client(|chain_client| {
        common::with_wallet(chain_client, |rt, sender, receiver| {
            rt.block_on(test_wallet_async(sender, receiver))
        })
    }) {
        println!("err: {:?}", e);
        assert!(false)
    }
}

#[test]
fn test_wallet_install_package() {
    if let Err(e) = run_test_wallet_install_package() {
        println!("err: {:?}", e);
        assert!(false)
    }
}

#[test]
fn test_deploy_custom_module_by_mock_client() {
    if let Err(e) = run_test_deploy_custom_module_by_mock_client() {
        println!("err: {:?}", e);
        assert!(false)
    }
}

#[test]
fn test_gobang() {
    if let Err(e) = run_test_gobang() {
        println!("err: {:?}", e);
        assert!(false)
    }
}

fn run_test_wallet_install_package() -> Result<()> {
    run_with_mock_client(|chain_client| {
        common::with_wallet(chain_client, |rt, alice, bob| {
            rt.block_on(async move {
                let transfer_code = alice
                    .get_script("libra".to_string(), "transfer".to_string())
                    .await?
                    .unwrap();
                let package = ChannelScriptPackage::new("test".to_string(), vec![transfer_code]);
                alice.install_package(package.clone()).await?;
                bob.install_package(package.clone()).await?;
                common::open_channel(alice.clone(), bob.clone(), 100000, 100000).await?;
                common::execute_script(
                    alice.clone(),
                    bob.clone(),
                    "test",
                    "transfer",
                    vec![
                        TransactionArgument::Address(bob.account()),
                        TransactionArgument::U64(10000),
                    ],
                )
                .await?;
                Ok(())
            })
        })
    })?;

    Ok(())
}

fn run_test_deploy_custom_module_by_mock_client() -> Result<()> {
    run_with_mock_client(|chain_client| test_deploy_custom_module(chain_client))
}

fn run_test_gobang() -> Result<()> {
    run_with_mock_client(|chain_client| {
        common::with_wallet(chain_client, |rt, alice, bob| {
            rt.block_on(async move {
                deploy_custom_module_and_script(alice.clone(), bob.clone(), "test_gobang").await
            })
        })
    })

    //    open_channel(alice.clone(), bob.clone(), 100, 100)?;

    //    execute_script(alice.clone(), bob.clone(), "scripts", "new", vec![TransactionArgument::Address(bob.account())])?;
    //    execute_script(bob.clone(), alice.clone(), "scripts", "join", vec![])?;
    //    execute_script(
    //        alice.clone(),
    //        bob.clone(),
    //        "scripts",
    //        "play",
    //        vec![TransactionArgument::U64(2), TransactionArgument::U64(2), TransactionArgument::Address(bob.account())],
    //    )?;
    //    execute_script(
    //        bob.clone(),
    //        alice.clone(),
    //        "scripts",
    //        "play",
    //        vec![TransactionArgument::U64(3), TransactionArgument::U64(2), TransactionArgument::Address(alice.account())],
    //    )?;
    //    execute_script(
    //        alice.clone(),
    //        bob.clone(),
    //        "scripts",
    //        "play",
    //        vec![TransactionArgument::U64(2), TransactionArgument::U64(3), TransactionArgument::Address(bob.account())],
    //    )?;
    //    execute_script(
    //        bob.clone(),
    //        alice.clone(),
    //        "scripts",
    //        "play",
    //        vec![TransactionArgument::U64(3), TransactionArgument::U64(3), TransactionArgument::Address(alice.account())],
    //    )?;
    //    execute_script(
    //        alice.clone(),
    //        bob.clone(),
    //        "scripts",
    //        "play",
    //        vec![TransactionArgument::U64(2), TransactionArgument::U64(4), TransactionArgument::Address(bob.account())],
    //    )?;
    //    execute_script(
    //        bob.clone(),
    //        alice.clone(),
    //        "scripts",
    //        "play",
    //        vec![TransactionArgument::U64(3), TransactionArgument::U64(4), TransactionArgument::Address(alice.account())],
    //    )?;
    //    execute_script(
    //        alice.clone(),
    //        bob.clone(),
    //        "scripts",
    //        "play",
    //        vec![TransactionArgument::U64(2), TransactionArgument::U64(5), TransactionArgument::Address(bob.account())],
    //    )?;
    //    execute_script(
    //        bob.clone(),
    //        alice.clone(),
    //        "scripts",
    //        "play",
    //        vec![TransactionArgument::U64(3), TransactionArgument::U64(5), TransactionArgument::Address(alice.account())],
    //    )?;
    //    execute_script(
    //        alice.clone(),
    //        bob.clone(),
    //        "scripts",
    //        "play",
    //        vec![TransactionArgument::U64(2), TransactionArgument::U64(6), TransactionArgument::Address(bob.account())],
    //    )?;
    //    execute_script(
    //        alice.clone(),
    //        bob.clone(),
    //        "scripts",
    //        "check_score",
    //        vec![TransactionArgument::U64(1)],
    //    )?;
}

fn run_with_mock_client<F, T>(mut f: F) -> T
where
    F: FnMut(Arc<dyn ChainClient>) -> T,
{
    libra_logger::try_init_for_testing();
    let (mock_chain_service, _handle) = MockChainClient::new();
    std::thread::sleep(Duration::from_millis(1500));
    let chain_client = Arc::new(mock_chain_service);
    f(chain_client)
}
