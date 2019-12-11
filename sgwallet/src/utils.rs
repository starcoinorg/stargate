// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use failure::prelude::*;
use libra_crypto::HashValue;
use libra_types::account_address::AccountAddress;
use libra_types::transaction::TransactionArgument;
use sgtypes::channel_transaction::ChannelOp;

/// check if the `op` is a htlc transfer
pub fn is_htlc_transfer(op: &ChannelOp) -> bool {
    match op {
        ChannelOp::Action {
            module_address,
            module_name,
            function_name,
        } => {
            module_address == &AccountAddress::default()
                && module_name.as_str() == "ChannelScript"
                && function_name.as_str() == "send_payment"
        }
        _ => false,
    }
}
/// check if the `op` is a htlc transfer
pub fn is_htlc_receive(op: &ChannelOp) -> bool {
    match op {
        ChannelOp::Action {
            module_address,
            module_name,
            function_name,
        } => {
            module_address == &AccountAddress::default()
                && module_name.as_str() == "ChannelScript"
                && function_name.as_str() == "receive_payment"
        }
        _ => false,
    }
}
/// get hash lock value from `args` which should be the args of `ChannelScript.send_payment`
pub fn parse_htlc_hash_lock(args: &[TransactionArgument]) -> Result<HashValue> {
    ensure!(args.len() == 4, "send_payment should have 4 args");
    match &args[2] {
        TransactionArgument::ByteArray(d) => HashValue::from_slice(d.as_bytes()),
        _ => bail!("the third arg of send_payment should be byte array"),
    }
}

/// get preimage value from `args` which should be the args of `ChannelScript.receive_payment`
pub fn parse_htlc_preimage(args: &[TransactionArgument]) -> Result<HashValue> {
    ensure!(args.len() == 1, "receive_payment should have 1 args");
    match &args[0] {
        TransactionArgument::ByteArray(d) => HashValue::from_slice(d.as_bytes()),
        _ => bail!("the 2th arg of receive_payment should be byte array"),
    }
}