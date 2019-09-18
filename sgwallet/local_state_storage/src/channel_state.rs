use std::collections::BTreeMap;

use crypto::ed25519::Ed25519Signature;
use failure::prelude::*;
use types::access_path::{AccessPath, DataPath};
use types::account_address::AccountAddress;
use types::transaction::{Version, TransactionOutput, ChannelWriteSetPayload};
use types::write_set::{WriteOp, WriteSet};
use types::channel_account::ChannelAccountResource;

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
pub struct ChannelState {
    /// The version of chain when this ChannelState init.
    //TODO need version?
    //version: Version,
    account: AccountAddress,
    participant: AccountAddress,
    /// Current account state in this channel
    account_state: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Participant state in this channel
    participant_state: BTreeMap<Vec<u8>, Vec<u8>>,
    witness_data: Option<WitnessData>,
}

impl ChannelState {
    pub fn new(account: AccountAddress, participant: AccountAddress, my_state: BTreeMap<Vec<u8>, Vec<u8>>,
               participant_state: BTreeMap<Vec<u8>, Vec<u8>>) -> Self {
        Self {
            account,
            participant,
            account_state: my_state,
            participant_state,
            witness_data: None,
        }
    }

    pub fn get(&self, access_path: &AccessPath) -> Option<Vec<u8>> {
        match self.witness_data().and_then(|witness_data|witness_data.write_set.get(access_path)){
            Some(op) => match op {
                WriteOp::Value(value) => Some(value.clone()),
                WriteOp::Deletion => None
            }
            None => if access_path.address == self.participant{
                self.participant_state.get(&access_path.path).cloned()
            }else{
                self.account_state.get(&access_path.path).cloned()
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
                    let mut state = if ap.address == self.account{
                        &mut self.account_state
                    }else if ap.address == self.participant {
                        &mut self.participant_state
                    }else{
                        bail!("Unexpect witness_payload access_path {:?} apply to channel state {}", ap, self.participant);
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

    pub fn witness_data(&self) -> Option<&WitnessData> {
        self.witness_data.as_ref()
    }

    pub fn account_resource(&self) -> ChannelAccountResource{
        self.get(&AccessPath::new_for_data_path(self.account,DataPath::channel_account_path(self.participant)))
            .and_then(|value|ChannelAccountResource::make_from(value).ok()).expect("channel must contains ChannelAccountResource")
    }

    pub fn participant_account_resource(&self) -> ChannelAccountResource{
        self.get(&AccessPath::new_for_data_path(self.participant,DataPath::channel_account_path(self.account)))
            .and_then(|value|ChannelAccountResource::make_from(value).ok()).expect("channel must contains ChannelAccountResource")
    }
}