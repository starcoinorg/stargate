// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{commands::*, sg_client_proxy::SGClientProxy};
use sgtypes::account_state::AccountState;

/// Major command for account related operations.
pub struct AccountCommand {}

impl Command for AccountCommand {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["account", "a"]
    }
    fn get_description(&self) -> &'static str {
        "Account operations"
    }
    fn execute(&self, client: &mut SGClientProxy, params: &[&str]) {
        let commands: Vec<Box<dyn Command>> = vec![
            Box::new(AccountCommandCreate {}),
            Box::new(AccountCommandMint {}),
            Box::new(AccountCommandState {}),
            Box::new(AccountCommandRecoverWallet {}),
            Box::new(AccountCommandWriteRecovery {}),
        ];

        subcommand_execute(&params[0], commands, client, &params[1..]);
    }
}

/// Sub command to create a random account. The account will not be saved on chain.
pub struct AccountCommandCreate {}

impl Command for AccountCommandCreate {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["create", "c"]
    }
    fn get_description(&self) -> &'static str {
        "Create an account. Returns reference ID to use in other operations"
    }
    fn execute(&self, client: &mut SGClientProxy, _params: &[&str]) {
        println!(">> Creating/retrieving next account from wallet");
        match client.create_account() {
            Ok((addr, index)) => println!(
                "Created/retrieved address {},index {:?}",
                hex::encode(addr),
                index
            ),
            Err(e) => report_error("Error creating account", e),
        }
    }
}

pub struct AccountCommandMint {}

impl Command for AccountCommandMint {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["mint", "mintb", "m", "mb"]
    }
    fn get_params_help(&self) -> &'static str {
        "<receiver_account_ref_id>|<receiver_account_address> <number_of_coins>"
    }
    fn get_description(&self) -> &'static str {
        "Mint coins to the account. Suffix 'b' is for blocking"
    }
    fn execute(&self, client: &mut SGClientProxy, params: &[&str]) {
        if params.len() < 3 {
            println!("Invalid number of arguments for mint");
            return;
        }

        match client.faucet(params[2].parse::<u64>().unwrap(), params[1]) {
            Ok(_result) => println!("mint success"),
            Err(e) => report_error("Error mint account", e),
        }
    }
}

pub struct AccountCommandState {}

impl Command for AccountCommandState {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["state", "s"]
    }
    fn get_params_help(&self) -> &'static str {
        "<receiver_account_ref_id>|<receiver_account_address>"
    }
    fn get_description(&self) -> &'static str {
        "get state of account"
    }
    fn execute(&self, client: &mut SGClientProxy, params: &[&str]) {
        if params.len() < 2 {
            println!("Invalid number of arguments for state");
            return;
        }
        match client.account_state(params[1]) {
            Ok((version, result, proof)) => match result {
                Some(data) => {
                    let account_resource =
                        AccountState::from_account_state_blob(version, data, proof)
                            .unwrap()
                            .get_account_resource();
                    match account_resource {
                        Some(resource) => {
                            println!("account state is {:?}", resource);
                        }
                        None => {
                            println!("no such account state ");
                        }
                    }
                }
                None => {
                    println!("no such account state ");
                }
            },
            Err(e) => report_error("Error mint account", e),
        }
    }
}

/// Sub command to recover wallet from the file specified.
pub struct AccountCommandRecoverWallet {}

impl Command for AccountCommandRecoverWallet {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["recover", "r"]
    }
    fn get_params_help(&self) -> &'static str {
        "<file_path>"
    }
    fn get_description(&self) -> &'static str {
        "Recover Libra wallet from the file path"
    }
    fn execute(&self, client: &mut SGClientProxy, params: &[&str]) {
        println!(">> Recovering Wallet");
        if params.len() < 1 {
            println!("Invalid number of arguments for recovery");
            return;
        }
        match client.recover_wallet_accounts(&params) {
            Ok(account_data) => {
                println!(
                    "Wallet recovered and the first {} child accounts were derived",
                    account_data.len()
                );
                for (index, address) in account_data.iter().enumerate() {
                    println!("#{} address {}", index, hex::encode(address));
                }
            }
            Err(e) => report_error("Error recovering Libra wallet", e),
        }
    }
}

/// Sub command to backup wallet to the file specified.
pub struct AccountCommandWriteRecovery {}

impl Command for AccountCommandWriteRecovery {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["write", "w"]
    }
    fn get_params_help(&self) -> &'static str {
        "<file_path>"
    }
    fn get_description(&self) -> &'static str {
        "Save Libra wallet mnemonic recovery seed to disk"
    }
    fn execute(&self, client: &mut SGClientProxy, params: &[&str]) {
        println!(">> Saving Libra wallet mnemonic recovery seed to disk");
        if params.len() < 1 {
            println!("Invalid number of arguments for write");
            return;
        }
        match client.write_recovery(&params) {
            Ok(_) => println!("Saved mnemonic seed to disk"),
            Err(e) => report_error("Error writing mnemonic recovery seed to file", e),
        }
    }
}
