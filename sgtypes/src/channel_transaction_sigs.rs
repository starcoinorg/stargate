// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use canonical_serialization::{CanonicalDeserialize, CanonicalDeserializer,
                              CanonicalSerialize, CanonicalSerializer};
use crypto::ed25519::{Ed25519PublicKey, Ed25519Signature};
use crypto::HashValue;
use failure::prelude::*;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

/// txn signature struct.
/// based on `is_sender_sig` and `is_travel`, the `signature` filed is used to sign different message.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum TxnSignature {
    SenderSig {
        channel_txn_signature: Ed25519Signature,
    },
    ReceiverSig {
        channel_script_body_signature: Ed25519Signature,
    },
}

impl TryFrom<crate::proto::sgtypes::TxnSignature> for TxnSignature {
    type Error = Error;

    fn try_from(proto: crate::proto::sgtypes::TxnSignature) -> Result<Self> {
        use crate::proto::sgtypes::TxnSignatureType as ProtoTxnSignatureType;
        let ret = match proto.sign_type() {
            ProtoTxnSignatureType::SenderSig => {
                TxnSignature::SenderSig { channel_txn_signature: Ed25519Signature::try_from(
                    proto.channel_txn_signature.as_slice())? }
            }
            ProtoTxnSignatureType::ReceiverSig => {
                TxnSignature::ReceiverSig { channel_script_body_signature: Ed25519Signature::
                try_from(proto.channel_script_body_signature.as_slice())? }
            }
        };
        Ok(ret)
    }
}

impl From<TxnSignature> for crate::proto::sgtypes::TxnSignature {
    fn from(sign: TxnSignature) -> Self {
        use crate::proto::sgtypes::TxnSignatureType as ProtoTxnSignatureType;
        let mut txn_sign = Self::default();

        match sign {
            TxnSignature::SenderSig { channel_txn_signature } => {
                txn_sign.set_sign_type(ProtoTxnSignatureType::SenderSig);
                txn_sign.channel_txn_signature = channel_txn_signature.to_bytes().to_vec();
            }
            TxnSignature::ReceiverSig { channel_script_body_signature } => {
                txn_sign.set_sign_type(ProtoTxnSignatureType::ReceiverSig);
                txn_sign.channel_script_body_signature = channel_script_body_signature.to_bytes().to_vec();
            }
        };
        txn_sign
    }
}

impl CanonicalSerialize for TxnSignature {
    fn serialize(&self, serializer: &mut impl CanonicalSerializer) -> Result<()> {
        match self {
            TxnSignature::SenderSig {
                channel_txn_signature,
            } => {
                serializer
                    .encode_u32(1)?
                    .encode_struct(channel_txn_signature)?;
            }
            TxnSignature::ReceiverSig {
                channel_script_body_signature,
            } => {
                serializer
                    .encode_u32(2)?
                    .encode_struct(channel_script_body_signature)?;
            }
        }
        Ok(())
    }
}

impl CanonicalDeserialize for TxnSignature {
    fn deserialize(deserializer: &mut impl CanonicalDeserializer) -> Result<Self>
        where
            Self: Sized,
    {
        let decoded_txn_type = deserializer.decode_u32()?;

        if decoded_txn_type == 1 {
            let signature = deserializer.decode_struct()?;
            Ok(TxnSignature::SenderSig {
                channel_txn_signature: signature,
            })
        } else if decoded_txn_type == 2 {
            let signature = deserializer.decode_struct()?;
            Ok(TxnSignature::ReceiverSig {
                channel_script_body_signature: signature,
            })
        } else {
            Err(format_err!(
                "ParseError: Unable to decode ChannelTransactionType, found {}",
                decoded_txn_type
            ))
        }
    }
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChannelTransactionSigs {
    /// The public key
    pub public_key: Ed25519PublicKey,
    /// tx signature
    pub signature: TxnSignature,
    // hash of output from libra raw tx
    pub write_set_payload_hash: HashValue,
    // signature on write_set_hash
    pub write_set_payload_signature: Ed25519Signature,
}

impl ChannelTransactionSigs {
    pub fn new(
        public_key: Ed25519PublicKey,
        signature: TxnSignature,
        write_set_payload_hash: HashValue,
        write_set_payload_signature: Ed25519Signature,
    ) -> Self {
        Self {
            public_key,
            signature,
            write_set_payload_hash,
            write_set_payload_signature,
        }
    }
}

impl CanonicalSerialize for ChannelTransactionSigs {
    fn serialize(&self, serializer: &mut impl CanonicalSerializer) -> Result<()> {
        serializer
            .encode_struct(&self.public_key)?
            .encode_struct(&self.signature)?
            .encode_bytes(self.write_set_payload_hash.as_ref())?
            .encode_struct(&self.write_set_payload_signature)?;
        Ok(())
    }
}

impl CanonicalDeserialize for ChannelTransactionSigs {
    fn deserialize(deserializer: &mut impl CanonicalDeserializer) -> Result<Self>
        where
            Self: Sized,
    {
        let public_key = deserializer.decode_struct()?;
        let signature = deserializer.decode_struct()?;
        let write_set_payload_hash =
            HashValue::from_slice(deserializer.decode_bytes()?.as_slice())?;
        let write_set_payload_signature = deserializer.decode_struct()?;
        Ok(Self {
            public_key,
            signature,
            write_set_payload_hash,
            write_set_payload_signature,
        })
    }
}

impl TryFrom<crate::proto::sgtypes::ChannelTransactionSigs> for ChannelTransactionSigs {
    type Error = Error;

    fn try_from(proto: crate::proto::sgtypes::ChannelTransactionSigs) -> Result<Self> {
        let public_key = Ed25519PublicKey::try_from(proto.public_key.as_slice())?;
        let signature = TxnSignature::try_from(proto.signature.unwrap())?;
        let write_set_payload_hash =
            HashValue::from_slice(proto.write_set_payload_hash.as_slice())?;
        let write_set_payload_signature = Ed25519Signature::try_from(
            proto.write_set_payload_signature.as_slice())?;
        Ok(ChannelTransactionSigs {
            public_key,
            signature,
            write_set_payload_hash,
            write_set_payload_signature,
        })
    }
}

impl From<ChannelTransactionSigs> for crate::proto::sgtypes::ChannelTransactionSigs {
    fn from(txn_sign: ChannelTransactionSigs) -> Self {
        Self {
            public_key: txn_sign.public_key.to_bytes().to_vec(),
            signature: Some(txn_sign.signature.into()),
            write_set_payload_hash: txn_sign.write_set_payload_hash.to_vec(),
            write_set_payload_signature: txn_sign.write_set_payload_signature.to_bytes().to_vec(),
        }
    }
}