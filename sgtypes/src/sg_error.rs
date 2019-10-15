use failure::prelude::*;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};
use std::{
    convert::TryFrom,
    fmt::{self, Formatter},
};

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
}

impl std::fmt::Display for SgErrorCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Into::<u32>::into(*self))
    }
}
