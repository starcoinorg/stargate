#![allow(clippy::unit_arg)]

use crypto::{
    hash::{AccountStateBlobHasher, CryptoHash, CryptoHasher},
    HashValue,
};
use failure::prelude::*;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Blob {
    blob: Vec<u8>,
}

impl AsRef<[u8]> for Blob {
    fn as_ref(&self) -> &[u8] {
        &self.blob
    }
}

impl From<Blob> for Vec<u8> {
    fn from(account_state_blob: Blob) -> Vec<u8> {
        account_state_blob.blob
    }
}

impl From<Vec<u8>> for Blob {
    fn from(blob: Vec<u8>) -> Blob {
        Blob { blob }
    }
}

impl CryptoHash for Blob {
    //TODO define custom hasher.
    type Hasher = AccountStateBlobHasher;

    fn hash(&self) -> HashValue {
        let mut hasher = Self::Hasher::default();
        hasher.write(&self.blob);
        hasher.finish()
    }
}

#[cfg(test)]
mod tests{
    use super::*;

    #[test]
    fn test_debug_does_not_panic() {
        format!("{:#?}", Blob::from(vec![1u8, 2u8, 3u8]));
    }

}
