// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0
use crate::impl_hash;
use failure::prelude::*;
use libra_crypto::{
    ed25519::{Ed25519PublicKey, Ed25519Signature},
    HashValue,
};
use libra_crypto_derive::CryptoHasher;
use libra_types::account_address::AccountAddress;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize, CryptoHasher)]
pub struct ChannelTransactionSigs {
    /// The signer
    pub address: AccountAddress,
    /// The signer's public key
    pub public_key: Ed25519PublicKey,
    /// tx signature
    //    pub signature: TxnSignature,
    /// signature of channel txn payload
    pub channel_payload_signature: Ed25519Signature,
    /// hash of output from libra raw tx
    pub witness_data_hash: HashValue,
    /// signature on write_set_hash
    pub witness_data_signature: Ed25519Signature,
    pub travel_output_witness_signature: Option<Ed25519Signature>,
}
impl_hash!(ChannelTransactionSigs, ChannelTransactionSigsHasher);

impl ChannelTransactionSigs {
    pub fn new(
        address: AccountAddress,
        public_key: Ed25519PublicKey,
        channel_payload_signature: Ed25519Signature,
        witness_data_hash: HashValue,
        witness_data_signature: Ed25519Signature,
        travel_output_witness_signature: Option<Ed25519Signature>,
    ) -> Self {
        Self {
            address,
            public_key,
            channel_payload_signature,
            witness_data_hash,
            witness_data_signature,
            travel_output_witness_signature,
        }
    }
}
//impl_hash!(ChannelTransactionSigs, ChannelTransactionSigsHasher);

impl TryFrom<crate::proto::sgtypes::ChannelTransactionSigs> for ChannelTransactionSigs {
    type Error = Error;

    fn try_from(proto: crate::proto::sgtypes::ChannelTransactionSigs) -> Result<Self> {
        let address = AccountAddress::try_from(proto.address.as_slice())?;
        let public_key = Ed25519PublicKey::try_from(proto.public_key.as_slice())?;
        let channel_payload_signature =
            Ed25519Signature::try_from(proto.channel_payload_signature.as_slice())?;
        let witness_data_hash = HashValue::from_slice(proto.witness_data_hash.as_slice())?;
        let witness_data_signature =
            Ed25519Signature::try_from(proto.witness_data_signature.as_slice())?;
        let travel_output_witness_signature = if proto.travel_output_witness_signature.len() == 0 {
            None
        } else {
            Some(Ed25519Signature::try_from(
                proto.travel_output_witness_signature.as_slice(),
            )?)
        };
        Ok(ChannelTransactionSigs {
            address,
            public_key,
            channel_payload_signature,
            witness_data_hash,
            witness_data_signature,
            travel_output_witness_signature,
        })
    }
}

impl From<ChannelTransactionSigs> for crate::proto::sgtypes::ChannelTransactionSigs {
    fn from(txn_sign: ChannelTransactionSigs) -> Self {
        Self {
            address: txn_sign.address.to_vec(),
            public_key: txn_sign.public_key.to_bytes().to_vec(),
            channel_payload_signature: txn_sign.channel_payload_signature.to_bytes().to_vec(),
            witness_data_hash: txn_sign.witness_data_hash.to_vec(),
            witness_data_signature: txn_sign.witness_data_signature.to_bytes().to_vec(),
            travel_output_witness_signature: txn_sign
                .travel_output_witness_signature
                .map(|s| s.to_bytes().to_vec())
                .unwrap_or_default(),
        }
    }
}
