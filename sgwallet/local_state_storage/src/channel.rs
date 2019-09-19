use std::collections::BTreeMap;

use crypto::ed25519::Ed25519Signature;
use failure::prelude::*;
use types::access_path::{AccessPath, DataPath};
use types::account_address::AccountAddress;
use types::transaction::{Version, TransactionOutput, ChannelWriteSetPayload};
use types::write_set::{WriteOp, WriteSet};
use types::channel_account::ChannelAccountResource;

#[derive(Clone, Debug)]
pub struct ChannelState{
    address: AccountAddress,
    state:BTreeMap<Vec<u8>, Vec<u8>>,
}

impl ChannelState{

    pub fn empty(address: AccountAddress) -> Self{
        Self{
            address,
            state: BTreeMap::new(),
        }
    }

    pub fn new(address: AccountAddress, state: BTreeMap<Vec<u8>,Vec<u8>>) -> Self{
        Self{
            address,
            state
        }
    }

    pub fn get(&self, path: &Vec<u8>) -> Option<&Vec<u8>>{
        self.state.get(path)
    }

    pub fn len(&self) -> usize {
        self.state.len()
    }

    pub fn remove(&mut self, path: &Vec<u8>) -> Option<Vec<u8>>{
        self.state.remove(path)
    }

    pub fn insert(&mut self, path: Vec<u8>, value: Vec<u8>) -> Option<Vec<u8>>{
        self.state.insert(path, value)
    }

}

#[derive(Clone, Debug, Default)]
pub struct WitnessData {
    pub channel_sequence_number: u64,
    pub write_set: WriteSet,
    pub signature: Option<Ed25519Signature>,
}

impl WitnessData {
    pub fn new(channel_sequence_number: u64, write_set: WriteSet, signature: Ed25519Signature) -> Self {
        Self {
            channel_sequence_number,
            write_set,
            signature:Some(signature),
        }
    }

    pub fn new_with_sequence_number(channel_sequence_number: u64) -> Self {
        Self {
            channel_sequence_number,
            write_set: WriteSet::default(),
            signature: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Channel {
    /// The version of chain when this ChannelState init.
    //TODO need version?
    //version: Version,
    /// Current account state in this channel
    account: ChannelState,
    /// Participant state in this channel
    participant: ChannelState,
    witness_data: Option<WitnessData>,
}

impl Channel {
    pub fn new(account: ChannelState,
               participant: ChannelState) -> Self {
        Self {
            account,
            participant,
            witness_data: None,
        }
    }

    pub fn get(&self, access_path: &AccessPath) -> Option<Vec<u8>> {
        match self.witness_data.as_ref().and_then(|witness_data|witness_data.write_set.get(access_path)){
            Some(op) => match op {
                WriteOp::Value(value) => Some(value.clone()),
                WriteOp::Deletion => None
            }
            None => if access_path.address == self.participant.address{
                self.participant.get(&access_path.path).cloned()
            }else if access_path.address == self.account.address {
                self.account.get(&access_path.path).cloned()
            }else{
                panic!("Unexpect access_path: {} for this channel: {:?}", access_path, self)
            }
        }
    }

    pub fn update_witness_data(&mut self, witness_payload: ChannelWriteSetPayload, signature: Ed25519Signature) {
        let ChannelWriteSetPayload{channel_sequence_number, write_set, receiver} = witness_payload;
        self.witness_data = Some(WitnessData {
            channel_sequence_number,
            write_set,
            signature: Some(signature),
        })
    }

    pub fn reset_witness_data(&mut self) {
        self.witness_data = None
    }

    pub fn apply_witness(&mut self, executed_onchain: bool, witness_payload: ChannelWriteSetPayload, signature: Ed25519Signature) -> Result<()>{
        if executed_onchain{
            for (ap,op) in witness_payload.write_set{
                if ap.is_channel_resource(){
                    let mut state = if ap.address == self.account.address{
                        &mut self.account
                    }else if ap.address == self.participant.address {
                        &mut self.participant
                    }else{
                        bail!("Unexpect witness_payload access_path {:?} apply to channel state {:?}", ap, self.participant);
                    };
                    match op{
                        WriteOp::Value(value) => state.insert(ap.path.clone(), value),
                        WriteOp::Deletion => state.remove(&ap.path)
                    };
                }
            }
            self.reset_witness_data();
        }else{
            self.update_witness_data(witness_payload, signature);
        }
        Ok(())
    }

    pub fn witness_data(&self) -> WitnessData {
        self.witness_data.as_ref().cloned().unwrap_or(WitnessData::new_with_sequence_number(self.account_resource().channel_sequence_number()))
    }

    fn get_channel_account_resource(&self, access_path:&AccessPath) -> ChannelAccountResource{
        self.get(access_path)
            .and_then(|value|ChannelAccountResource::make_from(value).ok()).expect("channel must contains ChannelAccountResource")
    }

    pub fn account_resource(&self) -> ChannelAccountResource{
        let access_path = AccessPath::new_for_data_path(self.account.address,DataPath::channel_account_path(self.participant.address));
        self.get_channel_account_resource(&access_path)
    }

    pub fn participant_account_resource(&self) -> ChannelAccountResource{
        let access_path = AccessPath::new_for_data_path(self.participant.address,DataPath::channel_account_path(self.account.address));
        self.get_channel_account_resource(&access_path)
    }
}