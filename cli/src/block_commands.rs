// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{commands::*, sg_client_proxy::SGClientProxy};

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
            Box::new(BlockDetail {}),
            Box::new(BlockDifficulty {}),
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
        println!(">> Query latest height");
        match client.latest_height() {
            Ok(height) => println!("latest height is : {:?}", height),
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

        let block_id = if params.len() > 1 {
            Some(params[1])
        } else {
            None
        };
        match client.get_block_summary_list_request(block_id) {
            Ok(list) => {
                for (index, block_summary) in list.blocks.iter().enumerate() {
                    println!(
                        "#{} height {} block {} id {:?} parent {} accumulator {:?} \
                         state {:?} miner {:?} nonce {} target {} algo {}",
                        index,
                        block_summary.height,
                        hex::encode(block_summary.block_id.to_vec()),
                        block_summary.block_id,
                        hex::encode(block_summary.parent_id.to_vec()),
                        block_summary.accumulator_root_hash,
                        block_summary.state_root_hash,
                        block_summary.miner,
                        block_summary.nonce,
                        block_summary.target,
                        block_summary.algo,
                    );
                }
            }
            Err(e) => report_error("Error query block list", e),
        }
    }
}

pub struct BlockDetail {}

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
            Ok(block_detail) => println!("block detail : {:?}", block_detail),
            Err(e) => report_error("Error query block detail", e),
        }
    }
}

pub struct BlockDifficulty {}

impl Command for BlockDifficulty {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["blockdifficulty", "d"]
    }
    fn get_description(&self) -> &'static str {
        "Block Difficulty"
    }
    fn execute(&self, client: &mut SGClientProxy, params: &[&str]) {
        println!(">> Query block difficulty");

        match client.block_difficulty(params) {
            Ok(block_difficulty) => println!("block difficulty : {:?}", block_difficulty),
            Err(e) => report_error("Error query block difficulty", e),
        }
    }
}
