use failure::prelude::*;

pub struct Hash {
    bytes:[u8; 32],
}

const HashLength :usize= 32;

impl Hash{
    pub fn from_slice(src: &[u8]) -> Result<Self> {
        ensure!(
            src.len() == HashLength,
            "HashValue decoding failed due to length mismatch. HashValue \
             length: {}, src length: {}",
            HashLength,
            src.len()
        );
        let mut value = Self::zero();
        value.bytes.copy_from_slice(src);
        Ok(value)
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    pub fn zero() -> Self {
        Self {
            bytes:[0; HashLength],
        }
    }

}