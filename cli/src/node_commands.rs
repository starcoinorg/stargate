// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{commands::*, sg_client_proxy::SGClientProxy};
use libra_crypto::hash::CryptoHash;

/// Major command for account related operations.
pub struct NodeCommand {}

impl Command for NodeCommand {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["node", "n"]
    }
    fn get_description(&self) -> &'static str {
        "Node operations"
    }
    fn execute(&self, client: &mut SGClientProxy, params: &[&str]) {
        let commands: Vec<Box<dyn Command>> = vec![
            Box::new(NodeCommandOpenChannel {}),
            Box::new(NodeCommandPay {}),
            Box::new(NodeCommandWithdrawChannel {}),
            Box::new(NodeCommandChannelBalance {}),
            Box::new(NodeCommandDepositChannel {}),
        ];

        subcommand_execute(&params[0], commands, client, &params[1..]);
    }
}

pub struct NodeCommandOpenChannel {}

impl Command for NodeCommandOpenChannel {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["open channel ", "oc"]
    }

    fn get_params_help(&self) -> &'static str {
        "<remote_addr> <local_amount> <remote_amount>"
    }

    fn get_description(&self) -> &'static str {
        "open channel with remote addr"
    }

    fn execute(&self, client: &mut SGClientProxy, params: &[&str]) {
        if params.len() < 4 {
            println!("Invalid number of arguments for open channel");
            return;
        }

        match client.open_channel(params, true) {
            Ok(_result) => println!("open channel success"),
            Err(e) => report_error("Error open channel", e),
        }
    }
}

pub struct NodeCommandDepositChannel {}

impl Command for NodeCommandDepositChannel {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["deposit", "d"]
    }

    fn get_params_help(&self) -> &'static str {
        "<remote_addr> <local_amount> <remote_amount>"
    }

    fn get_description(&self) -> &'static str {
        "deposit money to channel"
    }

    fn execute(&self, client: &mut SGClientProxy, params: &[&str]) {
        if params.len() < 4 {
            println!("Invalid number of arguments for deposit channel");
            return;
        }

        match client.deposit(params, true) {
            Ok(_result) => println!("deposit success"),
            Err(e) => report_error("Error pay account", e),
        }
    }
}

pub struct NodeCommandPay {}

impl Command for NodeCommandPay {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["pay", "p"]
    }

    fn get_params_help(&self) -> &'static str {
        "<remote_addr> <amount>"
    }

    fn get_description(&self) -> &'static str {
        "off chain pay"
    }

    fn execute(&self, client: &mut SGClientProxy, params: &[&str]) {
        if params.len() < 3 {
            println!("Invalid number of arguments for pay");
            return;
        }

        match client.off_chain_pay(params, true) {
            Ok(_result) => println!("pay success"),
            Err(e) => report_error("Error pay account", e),
        }
    }
}

pub struct NodeCommandWithdrawChannel {}

impl Command for NodeCommandWithdrawChannel {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["withdraw", "wd"]
    }

    fn get_params_help(&self) -> &'static str {
        "<remote_addr> <local_amount> <remote_amount>"
    }

    fn get_description(&self) -> &'static str {
        "withdraw money from channel"
    }

    fn execute(&self, client: &mut SGClientProxy, params: &[&str]) {
        if params.len() < 4 {
            println!("Invalid number of arguments for withdrawl from channel");
            return;
        }

        match client.withdraw(params, true) {
            Ok(_result) => println!("withdraw success"),
            Err(e) => report_error("Error pay account", e),
        }
    }
}

pub struct NodeCommandChannelBalance {}

impl Command for NodeCommandChannelBalance {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["channel balance ", "cb"]
    }

    fn get_params_help(&self) -> &'static str {
        "<remote_addr>"
    }

    fn get_description(&self) -> &'static str {
        "get balance of channel"
    }

    fn execute(&self, client: &mut SGClientProxy, params: &[&str]) {
        if params.len() < 2 {
            println!("Invalid number of arguments for get channel balance");
            return;
        }

        match client.channel_balance(params, true) {
            Ok(result) => println!("balance is {}", result.balance),
            Err(e) => report_error("Error pay account", e),
        }
    }
}

pub struct NodeCommandQueryProposal {}

impl Command for NodeCommandQueryProposal {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["transaction proposal ", "tp"]
    }

    fn get_params_help(&self) -> &'static str {
        "<remote_addr>"
    }

    fn get_description(&self) -> &'static str {
        "get transaction proposal"
    }

    fn execute(&self, client: &mut SGClientProxy, params: &[&str]) {
        if params.len() < 2 {
            println!("Invalid number of arguments for get transaction proposal");
            return;
        }

        match client.get_channel_transaction_proposal(params) {
            Ok(result) => match result.channel_transaction {
                Some(t) => {
                    println!(
                        "channel transction from {},hash is {}",
                        t.channel_address(),
                        t.hash()
                    );
                }
                None => println!("no channel transaction proposal"),
            },
            Err(e) => report_error("Error pay account", e),
        }
    }
}

pub struct NodeCommandProposal {}

impl Command for NodeCommandProposal {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["transaction proposal action", "tpa"]
    }

    fn get_params_help(&self) -> &'static str {
        "<remote_addr> <transaction_hash> <approve/reject>"
    }

    fn get_description(&self) -> &'static str {
        "action transaction proposal"
    }

    fn execute(&self, client: &mut SGClientProxy, params: &[&str]) {
        if params.len() < 4 {
            println!("Invalid number of arguments for action transaction proposal");
            return;
        }

        match client.channel_transaction_proposal(params) {
            Ok(_) => {
                println!("success!");
            }
            Err(e) => report_error("Error pay account", e),
        }
    }
}
