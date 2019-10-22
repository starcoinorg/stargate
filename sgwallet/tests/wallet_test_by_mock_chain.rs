// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::wallet_test_helper::{
    deploy_custom_module_and_script, execute_script, open_channel, setup_wallet,
    test_deploy_custom_module, test_wallet,
};
use failure::prelude::*;
use libra_types::transaction::TransactionArgument;
use sgchain::star_chain_client::MockChainClient;
use sgtypes::script_package::ChannelScriptPackage;
use std::sync::Arc;

pub mod wallet_test_helper;

#[test]
fn test_wallet_with_mock_client() {
    run_test_wallet_with_mock_client().unwrap();
}

#[test]
fn test_wallet_install_package() {
    run_test_wallet_install_package().unwrap();
}

#[test]
fn test_deploy_custom_module_by_mock_client() {
    run_test_deploy_custom_module_by_mock_client().unwrap();
}

#[test]
fn test_vector() {
    run_test_vector().unwrap();
}

#[test]
fn test_gobang() {
    run_test_gobang().unwrap();
}

fn run_test_wallet_with_mock_client() -> Result<()> {
    let (mock_chain_service, _handle) = MockChainClient::new();
    let chain_client = Arc::new(mock_chain_service);
    test_wallet(chain_client)
}

fn run_test_wallet_install_package() -> Result<()> {
    ::logger::try_init_for_testing();
    let init_balance = 1000000;

    let (mock_chain_service, _handle) = MockChainClient::new();
    let client = Arc::new(mock_chain_service);

    let alice = Arc::new(setup_wallet(client.clone(), init_balance)?);
    let bob = Arc::new(setup_wallet(client.clone(), init_balance)?);

    let transfer_code = alice.get_script("libra", "transfer").unwrap();
    let package = ChannelScriptPackage::new("test".to_string(), vec![transfer_code]);
    alice.install_package(package.clone())?;
    bob.install_package(package.clone())?;

    open_channel(alice.clone(), bob.clone(), 100000, 100000)?;

    execute_script(
        alice.clone(),
        bob.clone(),
        "test",
        "transfer",
        vec![TransactionArgument::U64(10000)],
    )?;
    Ok(())
}

fn run_test_deploy_custom_module_by_mock_client() -> Result<()> {
    ::logger::try_init_for_testing();
    let (mock_chain_service, _handle) = MockChainClient::new();
    let chain_client = Arc::new(mock_chain_service);
    test_deploy_custom_module(chain_client)
}

fn run_test_vector() -> Result<()> {
    ::logger::try_init_for_testing();
    let init_balance = 1000000;

    let (mock_chain_service, _handle) = MockChainClient::new();
    let client = Arc::new(mock_chain_service);

    let alice = Arc::new(setup_wallet(client.clone(), init_balance)?);
    let bob = Arc::new(setup_wallet(client.clone(), init_balance)?);
    deploy_custom_module_and_script(alice.clone(), bob.clone(), "test_vector")?;

    open_channel(alice.clone(), bob.clone(), 100000, 100000)?;

    execute_script(
        alice.clone(),
        bob.clone(),
        "scripts",
        "move_vector_to_sender",
        vec![],
    )?;
    execute_script(
        alice.clone(),
        bob.clone(),
        "scripts",
        "move_vector_from_sender",
        vec![],
    )?;

    execute_script(
        alice.clone(),
        bob.clone(),
        "scripts",
        "move_vector_to_receiver",
        vec![],
    )?;
    execute_script(
        alice.clone(),
        bob.clone(),
        "scripts",
        "move_vector_from_receiver",
        vec![],
    )?;
    Ok(())
}

fn run_test_gobang() -> Result<()> {
    ::logger::try_init_for_testing();
    let init_balance = 1000000;

    let (mock_chain_service, _handle) = MockChainClient::new();
    let client = Arc::new(mock_chain_service);

    let alice = Arc::new(setup_wallet(client.clone(), init_balance)?);
    let bob = Arc::new(setup_wallet(client.clone(), init_balance)?);
    deploy_custom_module_and_script(alice.clone(), bob.clone(), "test_gobang")?;

    open_channel(alice.clone(), bob.clone(), 100, 100)?;

    execute_script(alice.clone(), bob.clone(), "scripts", "new", vec![])?;
    execute_script(bob.clone(), alice.clone(), "scripts", "join", vec![])?;
    execute_script(
        alice.clone(),
        bob.clone(),
        "scripts",
        "play",
        vec![TransactionArgument::U64(2), TransactionArgument::U64(2)],
    )?;
    execute_script(
        bob.clone(),
        alice.clone(),
        "scripts",
        "play",
        vec![TransactionArgument::U64(3), TransactionArgument::U64(2)],
    )?;
    execute_script(
        alice.clone(),
        bob.clone(),
        "scripts",
        "play",
        vec![TransactionArgument::U64(2), TransactionArgument::U64(3)],
    )?;
    execute_script(
        bob.clone(),
        alice.clone(),
        "scripts",
        "play",
        vec![TransactionArgument::U64(3), TransactionArgument::U64(3)],
    )?;
    execute_script(
        alice.clone(),
        bob.clone(),
        "scripts",
        "play",
        vec![TransactionArgument::U64(2), TransactionArgument::U64(4)],
    )?;
    execute_script(
        bob.clone(),
        alice.clone(),
        "scripts",
        "play",
        vec![TransactionArgument::U64(3), TransactionArgument::U64(4)],
    )?;
    execute_script(
        alice.clone(),
        bob.clone(),
        "scripts",
        "play",
        vec![TransactionArgument::U64(2), TransactionArgument::U64(5)],
    )?;
    execute_script(
        bob.clone(),
        alice.clone(),
        "scripts",
        "play",
        vec![TransactionArgument::U64(3), TransactionArgument::U64(5)],
    )?;
    execute_script(
        alice.clone(),
        bob.clone(),
        "scripts",
        "play",
        vec![TransactionArgument::U64(2), TransactionArgument::U64(6)],
    )?;
    execute_script(
        alice.clone(),
        bob.clone(),
        "scripts",
        "check_score",
        vec![TransactionArgument::U64(1)],
    )?;

    Ok(())
}
