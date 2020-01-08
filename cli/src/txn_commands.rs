// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{commands::*, sg_client_proxy::SGClientProxy};

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
            Box::new(TxnLatestVersion {}),
            Box::new(QueryTxnByVersion {}),
            Box::new(TxnList {}),
        ];

        subcommand_execute(&params[0], commands, client, &params[1..]);
    }
}

/// Sub command to query latest version.
pub struct TxnLatestVersion {}

impl Command for TxnLatestVersion {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["version", "v"]
    }
    fn get_description(&self) -> &'static str {
        "Query transaction latest version."
    }
    fn execute(&self, client: &mut SGClientProxy, _params: &[&str]) {
        println!(">> Query latest version.");
        match client.latest_version() {
            Ok(version) => println!("latest version is : {:?}", version),
            Err(e) => report_error("Error latest version", e),
        }
    }
}

/// Sub command to query txn by version.
pub struct QueryTxnByVersion {}

impl Command for QueryTxnByVersion {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["txn", "tx"]
    }
    fn get_description(&self) -> &'static str {
        "<version>"
    }
    fn execute(&self, client: &mut SGClientProxy, params: &[&str]) {
        println!(">> Query transaction by version.");
        match client.txn_by_version(params) {
            Ok(txn) => println!("transaction is : {:?}", txn),
            Err(e) => report_error("Error latest version", e),
        }
    }
}

pub struct TxnList {}

impl Command for TxnList {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["txnlist", "tl"]
    }
    fn get_description(&self) -> &'static str {
        "[version]"
    }
    fn execute(&self, client: &mut SGClientProxy, params: &[&str]) {
        println!(">> Query transaction list.");
        match client.txn_list(params) {
            Ok(txn_list) => println!("transaction list : {:?}", txn_list),
            Err(e) => report_error("Error latest version", e),
        }
    }
}
