// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

#![recursion_limit = "1024"]

mod invoice;
mod message_processor;
pub mod node;
mod node_command;

use std::time::{SystemTime, UNIX_EPOCH};

//#[cfg(test)]
pub mod test_helper;

mod node_test;

pub fn get_unix_ts() -> u64 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    since_the_epoch.as_millis() as u64
}
