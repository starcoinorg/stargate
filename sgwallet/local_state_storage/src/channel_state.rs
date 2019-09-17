use failure::prelude::*;
use types::account_address::AccountAddress;
use types::write_set::{WriteSet, WriteOp};
use crypto::ed25519::Ed25519Signature;
use types::access_path::AccessPath;

#[derive(Clone,Debug,Default)]
pub struct WitnessData {
    pub channel_sequence_number: u64,
    pub write_set: WriteSet,
    pub signature: Option<Ed25519Signature>,
}

impl WitnessData {

    pub fn new(channel_sequence_number: u64, write_set:WriteSet, signature:Ed25519Signature) ->Self{
        Self{
            channel_sequence_number,
            write_set,
            signature:Some(signature),
        }
    }

    pub fn new_with_sequence_number(channel_sequence_number: u64) -> Self{
        Self{
            channel_sequence_number,
            write_set: WriteSet::default(),
            signature: None
        }
    }
}

#[derive(Clone,Debug)]
pub struct ChannelState {
    pub participant: AccountAddress,
    pub witness_data: WitnessData,
}

impl ChannelState {

    pub fn new(participant: AccountAddress, witness_data: WitnessData) -> Self{
        Self{
            participant,
            witness_data
        }
    }

    pub fn get(&self, access_path: &AccessPath) -> Option<&WriteOp> {
        self.witness_data.write_set.get(access_path)
    }

    pub fn update_witness_data(&mut self, channel_sequence_number: u64, write_set: WriteSet, signature: Ed25519Signature){
        self.witness_data = WitnessData{
            channel_sequence_number,
            write_set,
            signature: Some(signature),
        }
    }

    pub fn reset_witness_data(&mut self, channel_sequence_number: u64){
        self.witness_data = WitnessData::new_with_sequence_number(channel_sequence_number)
    }

    pub fn witness_data(&self) -> &WitnessData{
        &self.witness_data
    }
}