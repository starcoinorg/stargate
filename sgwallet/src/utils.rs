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
            module_address == AccountAddress::default()
                && module_name.as_str() == "ChannelScript"
                && function_name.as_str() == "send_payment"
        }
        _ => false,
    }
}

pub fn parse_htlc_hash_lock(args: &[TransactionArgument]) -> Result<HashValue> {
    unimplemented!()
}
