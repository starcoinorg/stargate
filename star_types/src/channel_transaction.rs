use failure::prelude::*;
use crypto::ed25519::{Ed25519PublicKey, Ed25519Signature};
use types::account_address::AccountAddress;
use types::transaction::{RawTransaction, SignedTransaction, TransactionStatus, ChannelWriteSetPayload, TransactionOutput, ChannelScriptPayload, TransactionPayload};
use types::contract_event::ContractEvent;
use types::write_set::WriteSet;
use types::vm_error::VMStatus;
use proto_conv::{FromProto, IntoProto};
use core::convert::TryFrom;
use protobuf::RepeatedField;
use canonical_serialization::{CanonicalSerialize, CanonicalSerializer, CanonicalDeserializer, CanonicalDeserialize, SimpleDeserializer, SimpleSerializer};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChannelTransaction {
    /// The sender signed transaction
    pub txn: SignedTransaction,

    pub witness_payload: ChannelWriteSetPayload,

    /// the signature of witness_payload
    pub witness_signature: Ed25519Signature,
}

impl ChannelTransaction {
    pub fn new(txn: SignedTransaction, witness_payload: ChannelWriteSetPayload, witness_signature: Ed25519Signature) -> Self {
        Self {
            txn,
            witness_payload,
            witness_signature,
        }
    }

//    pub fn sign_by_receiver(&mut self, signer: impl TransactionOutputSigner) -> Result<()>{
//        assert_eq!(1, self.output_signatures.len());
//        let signature = signer.sign_txn_output(&self.output)?;
//        self.output_signatures.push(signature);
//        Ok(())
//    }

    pub fn txn(&self) -> &SignedTransaction {
        &self.txn
    }

    pub fn channel_script_payload(&self) -> Option<&ChannelScriptPayload> {
        match self.txn.payload(){
            TransactionPayload::ChannelScript(payload) => Some(payload),
            _ => None
        }
    }

    pub fn channel_write_set_payload(&self) -> Option<&ChannelWriteSetPayload> {
        match self.txn.payload(){
            TransactionPayload::ChannelWriteSet(payload) => Some(payload),
            _ => None
        }
    }

    pub fn witness_payload(&self) -> &ChannelWriteSetPayload{
        &self.witness_payload
    }

    pub fn witness_signature(&self) -> &Ed25519Signature {
        &self.witness_signature
    }

    pub fn is_travel_txn(&self) -> bool {
        self.witness_payload.write_set.contains_onchain_resource()
    }

    pub fn sender(&self) -> AccountAddress {
        self.txn.sender()
    }

    pub fn receiver(&self) -> AccountAddress {
        self.txn.receiver().expect("channel txn must contains receiver")
    }

    pub fn witness_payload_write_set(&self) -> &WriteSet {
        &self.witness_payload.write_set
    }
}

impl CanonicalSerialize for ChannelTransaction{

    fn serialize(&self, serializer: &mut impl CanonicalSerializer) -> Result<()> {
        serializer.encode_struct(&self.txn)?
            .encode_struct(&self.witness_payload)?
            .encode_bytes(&self.witness_signature.to_bytes())?;
        Ok(())
    }
}

impl CanonicalDeserialize for ChannelTransaction{

    fn deserialize(deserializer: &mut impl CanonicalDeserializer) -> Result<Self> where
        Self: Sized {
        let txn = deserializer.decode_struct()?;
        let witness_payload = deserializer.decode_struct()?;
        let signature_bytes = deserializer.decode_bytes()?;
        Ok(Self{
            txn,
            witness_payload,
            witness_signature: Ed25519Signature::try_from(signature_bytes.as_slice())?
        })
    }
}

impl FromProto for ChannelTransaction {
    type ProtoType = crate::proto::channel_transaction::ChannelTransaction;

    fn from_proto(mut object: Self::ProtoType) -> Result<Self> {
        let bytes = object.take_payload();
        Ok(SimpleDeserializer::deserialize(bytes.as_slice())?)
    }
}

impl IntoProto for ChannelTransaction {
    type ProtoType = crate::proto::channel_transaction::ChannelTransaction;

    fn into_proto(self) -> Self::ProtoType {
        let mut out = Self::ProtoType::new();
        out.set_payload(SimpleSerializer::serialize(&self).expect("serialize must success."));
        out
    }
}
