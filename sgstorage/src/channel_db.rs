// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::schema_db::{SchemaDB, SchemaIterator};
use crate::storage::SgStorage;
use crate::utils;
use failure::prelude::*;
use lazy_static::lazy_static;
use libra_types::account_address::{AccountAddress, ADDRESS_LENGTH};
use logger::prelude::*;
use metrics::OpMetrics;
use rocksdb::{Writable, WriteOptions};
use schemadb::schema::{KeyCodec, Schema, SeekKeyCodec, ValueCodec};
use schemadb::ReadOptions;
use schemadb::{SchemaBatch, WriteOp};
use std::io::Read;
use std::marker::PhantomData;
use std::sync::Arc;

lazy_static! {
    static ref OP_COUNTER: OpMetrics = OpMetrics::new_and_registered("sg_storage");
}

pub trait ChannelAddressProvider {
    fn owner_address(&self) -> AccountAddress;
    fn participant_address(&self) -> AccountAddress;
}

#[derive(Clone, Debug)]
pub struct ChannelDB {
    inner: Arc<SgStorage>,
    participant: AccountAddress,
}

unsafe impl Send for ChannelDB {}
unsafe impl Sync for ChannelDB {}

impl ChannelDB {
    pub fn new(participant: AccountAddress, inner: Arc<SgStorage>) -> Self {
        Self { inner, participant }
    }
}

impl SchemaDB for ChannelDB {
    fn get<S: Schema>(
        &self,
        schema_key: &<S as Schema>::Key,
    ) -> Result<Option<<S as Schema>::Value>>
    where
        S::Key: Clone,
    {
        // compose full key
        let k = prefix_key(
            self.participant.as_ref(),
            <S::Key as KeyCodec<S>>::encode_key(&schema_key)?,
        );
        let cf_handle = self.inner.get_cf_handle(S::COLUMN_FAMILY_NAME)?;
        let time = std::time::Instant::now();

        let result = self
            .inner
            .get_cf(cf_handle, &k)
            .map_err(convert_rocksdb_err)?;
        OP_COUNTER.observe_duration(&format!("db_get_{}", S::COLUMN_FAMILY_NAME), time.elapsed());

        result
            .map(|raw_value| <S::Value as ValueCodec<S>>::decode_value(&raw_value))
            .transpose()
    }

    fn put<S: Schema>(&self, key: &<S as Schema>::Key, value: &<S as Schema>::Value) -> Result<()> {
        let k = prefix_key(
            self.participant.as_ref(),
            <S::Key as KeyCodec<S>>::encode_key(&key)?,
        );
        let v = <S::Value as ValueCodec<S>>::encode_value(&value)?;
        let cf_handle = self.inner.get_cf_handle(S::COLUMN_FAMILY_NAME)?;

        self.inner
            .put_cf_opt(cf_handle, &k, &v, &default_write_options())
            .map_err(convert_rocksdb_err)
    }

    fn range_delete<S, SK>(&self, begin: &SK, end: &SK) -> Result<()>
    where
        S: Schema,
        SK: SeekKeyCodec<S>,
    {
        let raw_begin = prefix_key(self.participant.as_ref(), begin.encode_seek_key()?);
        let raw_end = prefix_key(self.participant.as_ref(), end.encode_seek_key()?);
        let cf_handle = self.inner.get_cf_handle(S::COLUMN_FAMILY_NAME)?;

        self.inner
            .delete_range_cf(&cf_handle, &raw_begin, &raw_end)
            .map_err(convert_rocksdb_err)
    }

    fn iter<'a, S: Schema + 'static>(
        &'a self,
        _opts: ReadOptions,
    ) -> Result<Box<dyn SchemaIterator<S> + 'a>> {
        let cf_handle = self.inner.get_cf_handle(S::COLUMN_FAMILY_NAME)?;
        let mut iter_opts = rocksdb::ReadOptions::default();
        iter_opts.set_prefix_same_as_start(false);

        let iter = self.inner.iter_cf_opt(cf_handle, iter_opts);
        let mut schema_iterator = ChannelSchemaIterator {
            db_iter: iter,
            participant_address: self.participant,
            schema: PhantomData,
        };
        let _ = schema_iterator.seek_to_first();
        Ok(Box::new(schema_iterator))
    }

    fn write_schemas(&self, batch: SchemaBatch) -> Result<()> {
        let db_batch = rocksdb::WriteBatch::new();
        for (cf_name, rows) in &batch.rows {
            let cf_handle = self.inner.get_cf_handle(cf_name)?;
            for (key, write_op) in rows {
                let key = prefix_key(self.participant.as_ref(), key.to_vec());
                match write_op {
                    WriteOp::Value(value) => db_batch.put_cf(cf_handle, &key, value),
                    WriteOp::Deletion => db_batch.delete_cf(cf_handle, &key),
                }
                .map_err(convert_rocksdb_err)?;
            }
        }

        self.inner
            .write_opt(&db_batch, &default_write_options())
            .map_err(convert_rocksdb_err)?;

        // Bump counters only after DB write succeeds.
        for (cf_name, rows) in batch.rows {
            for (key, write_op) in rows {
                match write_op {
                    WriteOp::Value(value) => OP_COUNTER.observe(
                        &format!("db_put_bytes_{}", cf_name),
                        (ADDRESS_LENGTH + key.len() + value.len()) as f64,
                    ),
                    WriteOp::Deletion => OP_COUNTER.inc(&format!("db_delete_{}", cf_name)),
                }
            }
        }

        // metric rocksdb cf size
        match self.inner.get_approximate_sizes_cf() {
            Ok(cf_sizes) => {
                for (cf_name, size) in cf_sizes {
                    OP_COUNTER.set(&format!("cf_size_bytes_{}", cf_name), size as usize);
                }
            }
            Err(err) => warn!(
                "Failed to get approximate size of column families: {}.",
                err
            ),
        }

        Ok(())
    }
}

impl ChannelAddressProvider for ChannelDB {
    #[inline]
    fn participant_address(&self) -> AccountAddress {
        self.participant
    }
    #[inline]
    fn owner_address(&self) -> AccountAddress {
        self.inner.owner_address()
    }
}

/// All the RocksDB methods return `std::result::Result<T, String>`. Since our methods return
/// `failure::Result<T>`, manual conversion is needed.
fn convert_rocksdb_err(msg: String) -> failure::Error {
    format_err!("RocksDB internal error: {}.", msg)
}

/// For now we always use synchronous writes. This makes sure that once the operation returns
/// `Ok(())` the data is persisted even if the machine crashes. In the future we might consider
/// selectively turning this off for some non-critical writes to improve performance.
fn default_write_options() -> WriteOptions {
    let mut opts = WriteOptions::new();
    opts.set_sync(true);
    opts
}

// prefix key with `prefix`, after that, `key` is empty
fn prefix_key(prefix: &[u8], mut key: Vec<u8>) -> Vec<u8> {
    let mut k = prefix.to_vec();
    k.append(&mut key);
    k
}

pub struct ChannelSchemaIterator<'a, S> {
    db_iter: rocksdb::DBIterator<&'a rocksdb::DB>,
    participant_address: AccountAddress,
    schema: PhantomData<S>,
}

impl<'a, S> ChannelSchemaIterator<'a, S>
where
    S: Schema,
{
    fn is_in_valid_range(&self) -> bool {
        self.db_iter.valid()
            && self
                .db_iter
                .key()
                .starts_with(self.participant_address.as_ref())
    }
    fn decode_kv(&self) -> Result<(S::Key, S::Value)> {
        let mut key = self.db_iter.key();
        let value = self.db_iter.value();
        let mut address_data = [0; ADDRESS_LENGTH];
        key.read_exact(&mut address_data)?;
        let participant_address = AccountAddress::new(address_data);
        debug_assert!(self.participant_address == participant_address);
        Ok((
            <S::Key as KeyCodec<S>>::decode_key(key)?,
            <S::Value as ValueCodec<S>>::decode_value(value)?,
        ))
    }
}

impl<'a, S> Iterator for ChannelSchemaIterator<'a, S>
where
    S: Schema,
{
    type Item = Result<(S::Key, S::Value)>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_in_valid_range() {
            let kv = self.decode_kv();
            let _ = self.db_iter.next();
            Some(kv)
        } else {
            return None;
        }
    }
}

impl<'a, S> SchemaIterator<S> for ChannelSchemaIterator<'a, S>
where
    S: Schema,
{
    fn seek_to_first(&mut self) -> bool {
        let seek_key = rocksdb::SeekKey::Key(self.participant_address.as_ref());
        self.db_iter.seek(seek_key)
    }

    fn seek_to_last(&mut self) -> bool {
        let prefix_next_key = utils::prefix_next(self.participant_address.as_ref());
        let seek_key = rocksdb::SeekKey::Key(&prefix_next_key);
        self.db_iter.seek_for_prev(seek_key)
    }

    fn seek(&mut self, seek_key: &S::Key) -> Result<bool> {
        let mut k = self.participant_address.to_vec();
        let mut key = <S::Key as KeyCodec<S>>::encode_key(seek_key)?;
        k.append(&mut key);
        drop(key);

        let seek_result = self.db_iter.seek(k.as_slice().into());
        match seek_result {
            false => Ok(false), // if this address is the last range
            true => {
                // check whether the seek result is in this address range
                let in_range = self
                    .db_iter
                    .key()
                    .starts_with(self.participant_address.as_ref());
                Ok(in_range)
            }
        }
    }

    fn seek_for_prev(&mut self, seek_key: &S::Key) -> Result<bool> {
        let mut k = self.participant_address.to_vec();
        let mut key = <S::Key as KeyCodec<S>>::encode_key(seek_key)?;
        k.append(&mut key);
        drop(key);
        let seek_result = self.db_iter.seek_for_prev(k.as_slice().into());
        match seek_result {
            false => Ok(false), // if this address is the first range
            true => {
                let in_range = self
                    .db_iter
                    .key()
                    .starts_with(self.participant_address.as_ref());
                Ok(in_range)
            }
        }
    }
}
