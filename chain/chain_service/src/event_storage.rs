use failure::prelude::*;
use std::collections::HashMap;
use crypto::{
    hash::{CryptoHash, EventAccumulatorHasher},
    HashValue,
};
use types::{
    contract_event::ContractEvent,
    event::EventKey,
    proof::{position::Position}, transaction::Version};
use accumulator::{HashReader, MerkleAccumulator};

type SeqNum = u64;
type Key = (EventKey, SeqNum);

type Index = u64;
type Value = (Version, Index);

pub struct EventStorage {
    event_store: Vec<Vec<ContractEvent>>,
    event_key_store: HashMap<Key, Value>,
    event_accumulator_store: Vec<Vec<HashValue>>,
}

type EmptyAccumulator = MerkleAccumulator<EmptyReader, EventAccumulatorHasher>;

struct EmptyReader;

impl HashReader for EmptyReader {
    fn get(&self, _position: Position) -> Result<HashValue> {
        unreachable!()
    }
}

impl EventStorage {
    pub fn new() -> Self {
        let event_store: Vec<Vec<ContractEvent>> = vec![vec![]];
        let event_key_store: HashMap<Key, Value> = HashMap::new();
        let event_accumulator_store: Vec<Vec<HashValue>> = vec![vec![]];
        EventStorage { event_store, event_key_store, event_accumulator_store }
    }

    pub fn insert_events(&mut self, version: u64, events: &[ContractEvent]) -> Result<HashValue> {
        // 1.event
        let event_vec = events.to_vec();
        self.event_store.insert(version as usize, event_vec);

        // 2.event key
        events
            .iter()
            .enumerate()
            .for_each(|(idx, event)| {
                self.event_key_store.insert((*event.key(), event.sequence_number()), (version, idx as u64));
            });

        // 3.event accumulator
        let event_hashes: Vec<HashValue> = events.iter().map(ContractEvent::hash).collect();
        let (root_hash, mut writes) = EmptyAccumulator::append(&EmptyReader, 0, &event_hashes)?;
        writes.sort_by(|a: &(Position, HashValue), b: &(Position, HashValue)| a.0.to_inorder_index().cmp(&b.0.to_inorder_index()));
        let mut hash_values = vec![];
        for (_, hash) in writes {
            hash_values.push(hash);
        }
        self.event_accumulator_store.insert(version as usize, hash_values);

        Ok(root_hash)
    }
}