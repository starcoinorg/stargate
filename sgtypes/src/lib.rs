// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

pub mod account_resource_ext;
pub mod channel_transaction;
#[cfg(test)]
mod channel_transaction_test;
pub mod message;
pub mod proto;
pub mod resource;
pub mod sg_error;
pub mod system_event;

pub mod account_state;
pub mod channel;
#[cfg(test)]
mod resource_test;
pub mod script_package;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
