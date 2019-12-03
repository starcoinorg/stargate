// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use super::*;
use libra_crypto::HashValue;
use libra_types::vm_error::StatusCode;
use schemadb::schema::assert_encode_decode;
use sgtypes::channel_transaction_info::ChannelTransactionInfo;

#[test]
fn test_encode_decode() {
    let txn_info = ChannelTransactionInfo::new(
        HashValue::random(),
        HashValue::random(),
        HashValue::random(),
        HashValue::random(),
        StatusCode::EXECUTED,
        false,
        0,
    );
    assert_encode_decode::<ChannelTransactionInfoSchema>(&0u64, &txn_info);
}
