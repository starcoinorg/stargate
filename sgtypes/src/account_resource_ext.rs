// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use libra_types::account_config::AccountResource;

pub fn to_bytes(account_resource: &AccountResource) -> Result<Vec<u8>> {
    lcs::to_bytes(account_resource).map_err(Into::into)
}

pub fn from_bytes(value: &Vec<u8>) -> Result<AccountResource> {
    lcs::from_bytes(value.as_slice()).map_err(Into::into)
}
