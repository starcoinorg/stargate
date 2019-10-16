use crate::schema_db::{SchemaDB, SchemaIterator};
use crate::storage::SgStorage;
use failure::prelude::*;
use lazy_static::lazy_static;
use libra_types::account_address::{AccountAddress, ADDRESS_LENGTH};
use metrics::OpMetrics;
use rocksdb::{Writable, WriteOptions};
use schemadb::schema::{KeyCodec, Schema, SeekKeyCodec, ValueCodec};
use schemadb::ReadOptions;
use schemadb::{SchemaBatch, WriteOp};

use std::marker::PhantomData;
use std::sync::Arc;

//pub struct PrefixedSchema<S>(PhantomData<S>);
//impl<S> Schema for PrefixedSchema<S>
//where
//    S: Schema,
//{
//    const COLUMN_FAMILY_NAME: &'static str = S::COLUMN_FAMILY_NAME;
//    type Key = PrefixedSchemaKey<S::Key>;
//    type Value = S::Value;
//}
//
//#[derive(Debug, PartialEq)]
//pub struct PrefixedSchemaKey<K>
//where
//    K: Sized + PartialEq + Debug,
//{
//    pub prefix: AccountAddress,
//    pub key: K,
//}
//
//impl<S> KeyCodec<PrefixedSchema<S>> for PrefixedSchemaKey<S::Key>
//where
//    S: Schema + ?Sized,
//    S::Key: Sized + PartialEq + Debug,
//{
//    fn encode_key(&self) -> Result<Vec<u8>> {
//        let mut encoded_data = Vec::new();
//        encoded_data.write_all(self.prefix.as_ref())?;
//
//        encoded_data.write_all(&<S::Key as KeyCodec<S>>::encode_key(&self.key)?)?;
//        Ok(encoded_data)
//    }
//
//    fn decode_key(data: &[u8]) -> Result<Self> {
//        let mut data = &data[0..];
//        let mut prefix = [0u8; 32];
//        data.read_exact(&mut prefix)?;
//        let key = <S::Key as KeyCodec<S>>::decode_key(data)?;
//        Ok(Self {
//            prefix: AccountAddress::new(prefix),
//            key,
//        })
//    }
//}
//

lazy_static! {
    static ref OP_COUNTER: OpMetrics = OpMetrics::new_and_registered("schemadb");
}

pub trait ChannelAddressProvider {
    fn participant_address(&self) -> AccountAddress;
}

#[derive(Clone)]
pub struct ChannelDB {
    inner: Arc<SgStorage>,
    participant: AccountAddress,
}

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

    fn iter<S: Schema + 'static>(&self, _opts: ReadOptions) -> Result<Box<dyn SchemaIterator<S>>> {
        Ok(Box::new(ChannelSchemaIterator {
            channel_db: self.clone(),
            schema: PhantomData,
        }))
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

        Ok(())
    }
}

impl ChannelAddressProvider for ChannelDB {
    #[inline]
    fn participant_address(&self) -> AccountAddress {
        self.participant
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

pub struct ChannelSchemaIterator<S> {
    channel_db: ChannelDB,
    schema: PhantomData<S>,
}

impl<S> Iterator for ChannelSchemaIterator<S>
where
    S: Schema,
{
    type Item = Result<(S::Key, S::Value)>;

    fn next(&mut self) -> Option<Self::Item> {
        //        self.db_iter.kv().map(|(raw_key, raw_value)| {
        //            self.db_iter.next();
        //            Ok((
        //                <S::Key as KeyCodec<S>>::decode_key(&raw_key)?,
        //                <S::Value as ValueCodec<S>>::decode_value(&raw_value)?,
        //            ))
        //        })
        unimplemented!()
    }
}

impl<S> SchemaIterator<S> for ChannelSchemaIterator<S>
where
    S: Schema,
{
    fn seek_to_first(&mut self) -> bool {
        unimplemented!()
    }

    fn seek_to_last(&mut self) -> bool {
        unimplemented!()
    }

    fn seek(&mut self, _seek_key: &S::Key) -> Result<bool> {
        unimplemented!()
    }

    fn seek_for_prev(&mut self, _seek_key: &S::Key) -> Result<bool> {
        unimplemented!()
    }
}
