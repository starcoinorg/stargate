// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0
use super::schema::{
    channel_write_set_accumulator_schema::ChannelWriteSetAccumulatorSchema,
    channel_write_set_schema::ChannelWriteSetSchema,
};
use crate::schema_db::SchemaDB;
use accumulator::{HashReader, MerkleAccumulator};
use anyhow::Result;
use libra_crypto::hash::CryptoHash;
use libra_crypto::HashValue;
use libra_types::access_path::AccessPath;
use libra_types::proof::position::Position;
use libra_types::transaction::Version;
use libra_types::write_set::{WriteOp, WriteSet, WriteSetMut};
use schemadb::{ReadOptions, SchemaBatch};
use sgtypes::{hash::WriteSetAccumulatorHasher, write_set_item::WriteSetItem};

#[derive(Clone)]
pub struct ChannelWriteSetStore<S> {
    db: S,
}

impl<S> ChannelWriteSetStore<S> {
    pub fn new(db: S) -> Self {
        Self { db }
    }
}

impl<S> ChannelWriteSetStore<S>
where
    S: SchemaDB,
{
    pub fn put_write_set(
        &self,
        version: u64,
        write_set: WriteSet,
        cs: &mut SchemaBatch,
    ) -> Result<HashValue> {
        let write_set_items_hash = write_set
            .iter()
            .map(|(ap, wp)| WriteSetItem(ap.clone(), wp.clone()).hash())
            .collect::<Vec<_>>();

        let (root_hash, writes) = EmptyAccumulator::append(&EmptyReader, 0, &write_set_items_hash)?;
        for (pos, hash) in writes.into_iter() {
            cs.put::<ChannelWriteSetAccumulatorSchema>(&(version, pos), &hash)?;
        }

        for (idx, (ap, wp)) in write_set.into_iter().enumerate() {
            cs.put::<ChannelWriteSetSchema>(&(version, idx as u64), &WriteSetItem(ap, wp))?;
        }
        Ok(root_hash)
    }
}

impl<S> ChannelWriteSetStore<S>
where
    S: SchemaDB,
{
    /// Get all of the events given a transaction version.
    /// We don't need a proof for this because it's only used to get all events
    /// for a version which can be proved from the root hash of the event tree.
    pub fn get_write_set_by_version(&self, version: Version) -> Result<WriteSet> {
        let mut items: Vec<(AccessPath, WriteOp)> = vec![];

        let mut iter = self
            .db
            .iter::<ChannelWriteSetSchema>(ReadOptions::default())?;
        // Grab the first item and then iterate until we get all items for this version.
        iter.seek(&(version, 0))?;
        while let Some(((ver, _index), item)) = iter.next().transpose()? {
            if ver != version {
                break;
            }
            let WriteSetItem(ap, wp) = item;
            items.push((ap, wp));
        }
        WriteSetMut::new(items).freeze()
    }
}

type EmptyAccumulator = MerkleAccumulator<EmptyReader, WriteSetAccumulatorHasher>;

struct EmptyReader;

// Asserts `get()` is never called.
impl HashReader for EmptyReader {
    fn get(&self, _position: Position) -> Result<HashValue> {
        unreachable!()
    }
}
