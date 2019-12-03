use libra_crypto::HashValue;
use std::{convert::TryFrom, fmt};

use failure::prelude::*;

#[derive(Clone, Copy)]
pub struct SValue([u8; S_VALUE_LENGTH]);

const S_VALUE_LENGTH: usize = 33;

impl SValue {
    pub fn new(data: [u8; 33]) -> Self {
        SValue(data)
    }

    pub fn get_r(self) -> HashValue {
        return HashValue::from_sha3_256(&self.0[1..33]);
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl PartialEq for SValue {
    fn eq(&self, other: &Self) -> bool {
        for i in 1..33 {
            if self.0[i] != other.0[i] {
                return false;
            }
        }
        true
    }
}
impl Eq for SValue {}

impl AsRef<[u8]> for SValue {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for SValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> std::fmt::Result {
        // Forward to the LowerHex impl with a "0x" prepended (the # flag).
        write!(f, "{:#x}", self)
    }
}

impl fmt::Debug for SValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Forward to the LowerHex impl with a "0x" prepended (the # flag).
        write!(f, "{:#x}", self)
    }
}

impl fmt::LowerHex for SValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0.to_vec()))
    }
}

impl TryFrom<&[u8]> for SValue {
    type Error = failure::Error;

    /// Tries to convert the provided byte array into Address.
    fn try_from(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() == S_VALUE_LENGTH,
            "The Address {:?} is of invalid length",
            bytes
        );
        let mut addr = [0u8; S_VALUE_LENGTH];
        addr.copy_from_slice(bytes);
        Ok(Self(addr))
    }
}

impl TryFrom<&[u8; 33]> for SValue {
    type Error = failure::Error;

    /// Tries to convert the provided byte array into Address.
    fn try_from(bytes: &[u8; 33]) -> Result<Self> {
        Self::try_from(&bytes[..])
    }
}

impl TryFrom<Vec<u8>> for SValue {
    type Error = failure::Error;

    /// Tries to convert the provided byte buffer into Address.
    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        Self::try_from(&bytes[..])
    }
}

impl From<SValue> for Vec<u8> {
    fn from(addr: SValue) -> Vec<u8> {
        addr.0.to_vec()
    }
}

impl From<&SValue> for Vec<u8> {
    fn from(addr: &SValue) -> Vec<u8> {
        addr.0.to_vec()
    }
}
