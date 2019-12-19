// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{commands::*, sg_client_proxy::SGClientProxy};
use sgtypes::account_state::AccountState;

/// Major command for block explorer operations.
pub struct BlockCommand {}

impl Command for BlockCommand {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["block", "b"]
    }
    fn get_description(&self) -> &'static str {
        "Block explorer operations"
    }
    fn execute(&self, client: &mut SGClientProxy, params: &[&str]) {
        let commands: Vec<Box<dyn Command>> = vec![
            Box::new(BlockLatestHeight {}),
        ];

        subcommand_execute(&params[0], commands, client, &params[1..]);
    }
}

/// Latest Height
pub struct BlockLatestHeight {}

impl Command for BlockLatestHeight {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["height", "h"]
    }
    fn get_description(&self) -> &'static str {
        "Query latest height of block chain."
    }
    fn execute(&self, client: &mut SGClientProxy, _params: &[&str]) {
        println!(">> ");
        match client.latest_height() {
            Ok((height)) => println!(
                "latest height is : {:?}",
                height
            ),
            Err(e) => report_error("Error query latest height", e),
        }
    }
}
