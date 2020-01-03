// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0
use anyhow::{bail, ensure, Result};
use libra_crypto::HashValue;
use libra_types::{account_address::AccountAddress, transaction::TransactionArgument};
use sgtypes::{channel_transaction::ChannelOp, htlc::HtlcPayment};
pub(crate) mod actor_timer;
pub mod coerce_derive;
pub(crate) mod contract;

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
pub fn parse_htlc_payment(args: &[TransactionArgument]) -> Result<HtlcPayment> {
    ensure!(args.len() == 4, "send_payment should have 4 args");
    let amount = match &args[1] {
        TransactionArgument::U64(a) => *a,
        _ => bail!("1st arg of send_payment should be u64"),
    };
    let hash_lock = match &args[2] {
        TransactionArgument::ByteArray(d) => HashValue::from_slice(d.as_bytes())?,
        _ => bail!("3rd arg of send_payment should be byte array"),
    };
    let timeout = match &args[3] {
        TransactionArgument::U64(a) => *a,
        _ => bail!("4th arg of send_payment should be u64"),
    };
    Ok(HtlcPayment::new(hash_lock, amount, timeout))
}

/// get preimage value from `args` which should be the args of `ChannelScript.receive_payment`
pub fn parse_htlc_preimage(args: &[TransactionArgument]) -> Result<HashValue> {
    ensure!(args.len() == 1, "receive_payment should have 1 args");
    match &args[0] {
        TransactionArgument::ByteArray(d) => HashValue::from_slice(d.as_bytes()),
        _ => bail!("the 2th arg of receive_payment should be byte array"),
    }
}
