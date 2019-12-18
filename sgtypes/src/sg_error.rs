// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};

use libra_types::account_address::AccountAddress;

use crate::channel::ChannelStage;
use thiserror::Error;

#[allow(non_camel_case_types)]
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    PartialEq,
    PartialOrd,
    Ord,
    IntoPrimitive,
    TryFromPrimitive,
    Serialize,
    Deserialize,
)]
#[repr(u32)]
/// We don't derive Arbitrary on this enum because it is too large and breaks proptest. It is
/// written for a subset of these in proptest_types. We test conversion between this and protobuf
/// with a hand-written test.
pub enum SgErrorCode {
    UNKNOWN = 0,
    SEQUENCE_NUMBER_WRONG = 1,
    TIMEOUT = 2,
    CHANNEL_NOT_EXIST = 3,
    INVALID_CHANNEL_STAGE = 4,
    REJECT = 5,
    NOT_PATH = 6,
    BALANCE_NOT_ENOUGH = 7,
}

impl std::fmt::Display for SgErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Into::<u32>::into(*self))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
#[error("error code is  {0}, error message is {1}",
    self.error_code, self.error_message
)]
pub struct SgError {
    pub error_code: SgErrorCode,
    pub error_message: String,
}

impl SgError {
    pub fn new(error_code: SgErrorCode, error_message: String) -> Self {
        Self {
            error_code,
            error_message,
        }
    }

    pub fn new_channel_not_exist_error(participant: &AccountAddress) -> Self {
        Self {
            error_code: SgErrorCode::CHANNEL_NOT_EXIST,
            error_message: format!("Can not find channel by participant: {}", participant),
        }
    }

    pub fn new_invalid_channel_stage_error(stage: ChannelStage) -> Self {
        Self::new(
            SgErrorCode::INVALID_CHANNEL_STAGE,
            format!("Channel at stage: {:?}, unsupported this operator.", stage),
        )
    }
}
