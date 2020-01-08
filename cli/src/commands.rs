// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::block_commands::BlockCommand;
use crate::txn_commands::TxnCommand;
use crate::{
    account_commands::AccountCommand, dev_commands::DevCommand, node_commands::NodeCommand,
    sg_client_proxy::SGClientProxy,
};
use anyhow::Error;
use libra_types::account_address::ADDRESS_LENGTH;
use std::{collections::HashMap, sync::Arc};

pub fn report_error(msg: &str, e: Error) {
    println!("[ERROR] {}: {}", msg, pretty_format_error(e));
}

fn pretty_format_error(e: Error) -> String {
    if let Some(grpc_error) = e.downcast_ref::<grpcio::Error>() {
        if let grpcio::Error::RpcFailure(grpc_rpc_failure) = grpc_error {
            if grpc_rpc_failure.status == grpcio::RpcStatusCode::UNAVAILABLE
                || grpc_rpc_failure.status == grpcio::RpcStatusCode::DEADLINE_EXCEEDED
            {
                return "Server unavailable, please retry and/or check \
                        if host passed to the client is running"
                    .to_string();
            }
        }
    }

    return format!("{}", e);
}

pub fn get_commands() -> (
    Vec<Arc<dyn Command>>,
    HashMap<&'static str, Arc<dyn Command>>,
) {
    let commands: Vec<Arc<dyn Command>> = vec![
        Arc::new(AccountCommand {}),
        Arc::new(NodeCommand {}),
        Arc::new(DevCommand {}),
        Arc::new(TxnCommand {}),
        Arc::new(BlockCommand {}),
    ];
    let mut alias_to_cmd = HashMap::new();
    for command in &commands {
        for alias in command.get_aliases() {
            alias_to_cmd.insert(alias, Arc::clone(command));
        }
    }
    (commands, alias_to_cmd)
}

/// Parse a cmd string, the first element in the returned vector is the command to run
pub fn parse_cmd(cmd_str: &str) -> Vec<&str> {
    let input = &cmd_str[..];
    input.trim().split(' ').map(str::trim).collect()
}

pub fn subcommand_execute(
    parent_command_name: &str,
    commands: Vec<Box<dyn Command>>,
    client: &mut SGClientProxy,
    params: &[&str],
) {
    let mut commands_map = HashMap::new();
    for (i, cmd) in commands.iter().enumerate() {
        for alias in cmd.get_aliases() {
            if commands_map.insert(alias, i) != None {
                panic!("Duplicate alias {}", alias);
            }
        }
    }

    if params.is_empty() {
        print_subcommand_help(parent_command_name, &commands);
        return;
    }

    match commands_map.get(&params[0]) {
        Some(&idx) => commands[idx].execute(client, &params),
        _ => print_subcommand_help(parent_command_name, &commands),
    }
}

pub fn print_subcommand_help(parent_command: &str, commands: &[Box<dyn Command>]) {
    println!(
        "usage: {} <arg>\n\nUse the following args for this command:\n",
        parent_command
    );
    for cmd in commands {
        println!(
            "{} {}\n\t{}",
            cmd.get_aliases().join(" | "),
            cmd.get_params_help(),
            cmd.get_description()
        );
    }
    println!("\n");
}

/// Check whether the input string is a valid libra address.
pub fn is_address(data: &str) -> bool {
    match hex::decode(data) {
        Ok(vec) => vec.len() == ADDRESS_LENGTH,
        Err(_) => false,
    }
}

pub trait Command {
    /// all commands and aliases this command support.
    fn get_aliases(&self) -> Vec<&'static str>;
    /// string that describes params.
    fn get_params_help(&self) -> &'static str {
        ""
    }
    /// string that describes what the command does.
    fn get_description(&self) -> &'static str;
    /// code to execute.
    fn execute(&self, client: &mut SGClientProxy, params: &[&str]);
}
