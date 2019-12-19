// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{commands::*, sg_client_proxy::SGClientProxy};
use sgtypes::account_state::AccountState;

/// Major command for transaction explorer operations.
pub struct TxnCommand {}

impl Command for TxnCommand {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["transaction", "t"]
    }
    fn get_description(&self) -> &'static str {
        "Transaction explorer operations"
    }
    fn execute(&self, client: &mut SGClientProxy, params: &[&str]) {
        let commands: Vec<Box<dyn Command>> = vec![
            Box::new(AccountCommandCreate {}),
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

