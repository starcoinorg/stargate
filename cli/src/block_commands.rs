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
            Box::new(BlockList {}),
        ];

        subcommand_execute(&params[0], commands, client, &params[1..]);
    }
}

/// Sub command to query latest Height
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
            Ok(height) => println!(
                "latest height is : {:?}",
                height
            ),
            Err(e) => report_error("Error query latest height", e),
        }
    }
}

/// Sub command to query block list
pub struct BlockList {}

impl Command for BlockList {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["blocklist", "bl"]
    }
    fn get_description(&self) -> &'static str {
        "[block_id]"
    }
    fn execute(&self, client: &mut SGClientProxy, params: &[&str]) {
        println!(">> Query block summary list");

        let block_id = if params.len() > 0 {
            Some(params[0])
        } else {
            None
        };
        match client.get_block_summary_list_request(block_id) {
            Ok(list) => println!(
                "block summary list : {:?}",
                "list"
            ),
            Err(e) => report_error("Error query block list", e),
        }
    }
}

pub struct BlockDetail{}

impl Command for BlockDetail {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["blockdetail", "bd"]
    }
    fn get_description(&self) -> &'static str {
        "<block_id>"
    }
    fn execute(&self, client: &mut SGClientProxy, params: &[&str]) {
        println!(">> Query block info");

        match client.block_detail(params) {
            Ok(list) => println!(
                "block summary list : {:?}",
                "list"
            ),
            Err(e) => report_error("Error query block list", e),
        }
    }
}

