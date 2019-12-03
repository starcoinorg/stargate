// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0
pub mod account_resource_ext;
pub mod account_state;
pub mod channel;
pub mod channel_transaction;
pub mod channel_transaction_info;
pub mod channel_transaction_sigs;
#[cfg(test)]
mod channel_transaction_test;
pub mod channel_transaction_to_commit;
#[macro_use]
pub mod hash;
pub mod ledger_info;
pub mod message;
pub mod pending_txn;
pub mod proof;
pub mod proto;
pub mod resource;
#[cfg(test)]
mod resource_test;
pub mod s_value;
pub mod script_package;
pub mod sg_error;
pub mod signed_channel_transaction;
pub mod signed_channel_transaction_with_proof;
pub mod startup_info;
pub mod system_event;
pub mod write_set_item;
#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
