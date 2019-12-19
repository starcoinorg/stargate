pub mod proto;

use anyhow::Result;
use libra_types::account_address::AccountAddress;
use std::convert::TryFrom;

/// Helper to construct and parse [`proto::faucet::FaucetRequest`]
#[derive(PartialEq, Eq, Clone)]
pub struct FaucetRequest {
    pub address: AccountAddress,
    pub amount: u64,
}

impl FaucetRequest {
    /// Constructor.
    pub fn new(address: AccountAddress, amount: u64) -> Self {
        Self { address, amount }
    }
}

impl TryFrom<crate::proto::faucet::FaucetRequest> for FaucetRequest {
    type Error = anyhow::Error;

    fn try_from(proto: crate::proto::faucet::FaucetRequest) -> Result<Self> {
        let address = AccountAddress::try_from(&proto.address[..]).expect("FaucetRequest err.");
        let amount = proto.amount;

        Ok(Self { address, amount })
    }
}

impl From<FaucetRequest> for crate::proto::faucet::FaucetRequest {
    fn from(req: FaucetRequest) -> Self {
        Self {
            address: req.address.into(),
            amount: req.amount,
        }
    }
}

pub mod prelude {
    pub use super::*;
}
