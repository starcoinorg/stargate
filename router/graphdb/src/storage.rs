use crate::edge::Edge;
use crate::vertex::Vertex;
use failure::prelude::*;
use libra_logger::prelude::*;
use libra_types::account_address::AccountAddress;
use rocksdb::{rocksdb_options::ColumnFamilyDescriptor, CFHandle, DBOptions, ReadOptions};
use rocksdb::{Writable, WriteOptions};
use schemadb::schema::{KeyCodec, Schema, SeekKeyCodec, ValueCodec};
use schemadb::{define_schema, SchemaBatch, WriteOp};
use schemadb::{ColumnFamilyOptions, ColumnFamilyOptionsMap, DEFAULT_CF_NAME};

use std::marker::PhantomData;
use std::path::Path;

pub struct Storage {
    db: rocksdb::DB,
}

impl AsMut<rocksdb::DB> for Storage {
    fn as_mut(&mut self) -> &mut rocksdb::DB {
        &mut self.db
    }
}
impl AsRef<rocksdb::DB> for Storage {
    fn as_ref(&self) -> &rocksdb::DB {
        &self.db
    }
}

impl core::ops::Deref for Storage {
    type Target = rocksdb::DB;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl core::ops::DerefMut for Storage {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut()
    }
}

impl Storage {
    pub fn new(path: &Path) -> Self {
        let cfs = [
            (DEFAULT_CF_NAME, ColumnFamilyOptions::default()),
            ("Vertex", ColumnFamilyOptions::default()),
            ("Edge", ColumnFamilyOptions::default()),
        ]
        .iter()
        .cloned()
        .collect();

        Self::open(path, cfs).unwrap_or_else(|e| panic!("Graph DB open failed: {:?}", e))
    }

    pub fn open(path: &Path, mut cf_opts_map: ColumnFamilyOptionsMap) -> Result<Self> {
        let mut db_opts = DBOptions::new();

        db_opts.set_max_total_wal_size(1 << 30);

        if db_exists(path.as_ref()) {
            let db = rocksdb::DB::open_cf(
                db_opts,
                path.to_str().expect("should have path"),
                cf_opts_map.into_iter().collect(),
            )
            .map_err(convert_rocksdb_err)?;
            return Ok(Self { db });
        }

        db_opts.create_if_missing(true);

        let db = rocksdb::DB::open_cf(
            db_opts,
            path.to_str().expect("should have path"),
            vec![cf_opts_map
                .remove_entry(&DEFAULT_CF_NAME)
                .ok_or_else(|| format_err!("No \"default\" column family name found"))?],
        )
        .map_err(convert_rocksdb_err)?;

        let mut storage = Self { db };

        cf_opts_map
            .into_iter()
            .map(|(cf_name, cf_opts)| storage.create_cf((cf_name, cf_opts)))
            .collect::<Result<Vec<_>>>()?;

        Ok(storage)
    }

    fn create_cf<'a, T>(&mut self, cfd: T) -> Result<()>
    where
        T: Into<ColumnFamilyDescriptor<'a>>,
    {
        let _cf_handle = self.db.create_cf(cfd).map_err(convert_rocksdb_err)?;
        Ok(())
    }

    fn get_cf_handle(&self, cf_name: &str) -> Result<&CFHandle> {
        self.db.cf_handle(cf_name).ok_or_else(|| {
            format_err!(
                "DB::cf_handle not found for column family name: {}",
                cf_name
            )
        })
    }
}

impl Storage {
    pub fn _get<S: Schema>(
        &self,
        schema_key: &<S as Schema>::Key,
    ) -> Result<Option<<S as Schema>::Value>>
    where
        S::Key: Clone,
    {
        let cf_handle = self.get_cf_handle(S::COLUMN_FAMILY_NAME)?;

        let key = <S::Key as KeyCodec<S>>::encode_key(&schema_key)?;
        let result = self
            .db
            .get_cf(cf_handle, &key)
            .map_err(convert_rocksdb_err)?;

        result
            .map(|raw_value| <S::Value as ValueCodec<S>>::decode_value(&raw_value))
            .transpose()
    }

    pub fn put<S: Schema>(
        &self,
        key: &<S as Schema>::Key,
        value: &<S as Schema>::Value,
    ) -> Result<()> {
        let k = <S::Key as KeyCodec<S>>::encode_key(&key)?;
        let v = <S::Value as ValueCodec<S>>::encode_value(&value)?;
        let cf_handle = self.get_cf_handle(S::COLUMN_FAMILY_NAME)?;

        self.db
            .put_cf_opt(cf_handle, &k, &v, &default_write_options())
            .map_err(convert_rocksdb_err)
    }

    pub fn delete<S: Schema>(&self, key: &<S as Schema>::Key) -> Result<()> {
        let k = <S::Key as KeyCodec<S>>::encode_key(&key)?;

        let cf_handle = self.get_cf_handle(S::COLUMN_FAMILY_NAME)?;
        self.db
            .delete_cf(cf_handle, &k)
            .map_err(convert_rocksdb_err)
    }

    pub fn _range_delete<S, SK>(&self, begin: &SK, end: &SK) -> Result<()>
    where
        S: Schema,
        SK: SeekKeyCodec<S>,
    {
        let raw_begin = begin.encode_seek_key()?;
        let raw_end = end.encode_seek_key()?;
        let cf_handle = self.get_cf_handle(S::COLUMN_FAMILY_NAME)?;

        self.db
            .delete_range_cf(&cf_handle, &raw_begin, &raw_end)
            .map_err(convert_rocksdb_err)
    }

    pub fn _write_schemas(&self, batch: SchemaBatch) -> Result<()> {
        let db_batch = rocksdb::WriteBatch::new();
        for (cf_name, rows) in &batch.rows {
            let cf_handle = self.get_cf_handle(cf_name)?;
            for (key, write_op) in rows {
                let key = key.to_vec();
                match write_op {
                    WriteOp::Value(value) => db_batch.put_cf(cf_handle, &key, value),
                    WriteOp::Deletion => db_batch.delete_cf(cf_handle, &key),
                }
                .map_err(convert_rocksdb_err)?;
            }
        }

        self.db
            .write_opt(&db_batch, &default_write_options())
            .map_err(convert_rocksdb_err)?;

        // Bump counters only after DB write succeeds.
        for (cf_name, rows) in batch.rows {
            for (key, write_op) in rows {
                match write_op {
                    WriteOp::Value(value) => {
                        info!("cf_size_bytes_{},size {}", cf_name, key.len() + value.len())
                    }
                    WriteOp::Deletion => info!("db_delete_{}", cf_name),
                }
            }
        }

        Ok(())
    }

    pub fn iter<S: Schema>(&self, _opts: ReadOptions) -> Result<SchemaIterator<S>> {
        let cf_handle = self.get_cf_handle(S::COLUMN_FAMILY_NAME)?;
        let mut iter_opts = rocksdb::ReadOptions::default();
        iter_opts.set_prefix_same_as_start(false);

        let iter = self.db.iter_cf_opt(cf_handle, iter_opts);
        let mut schema_iterator = SchemaIterator {
            db_iter: iter,
            schema: PhantomData,
        };
        let _ = schema_iterator.seek_to_first();
        Ok(schema_iterator)
    }
}

fn default_write_options() -> WriteOptions {
    let mut opts = WriteOptions::new();
    opts.set_sync(true);
    opts
}

fn db_exists(path: &Path) -> bool {
    let rocksdb_current_file = path.join("CURRENT");
    rocksdb_current_file.is_file()
}

fn convert_rocksdb_err(msg: String) -> failure::Error {
    format_err!("RocksDB internal error: {}.", msg)
}

pub struct SchemaIterator<'a, S> {
    db_iter: rocksdb::DBIterator<&'a rocksdb::DB>,
    schema: PhantomData<S>,
}

impl<'a, S> SchemaIterator<'a, S>
where
    S: Schema,
{
    fn decode_kv(&self) -> Result<(S::Key, S::Value)> {
        let key = self.db_iter.key();
        let value = self.db_iter.value();
        Ok((
            <S::Key as KeyCodec<S>>::decode_key(key)?,
            <S::Value as ValueCodec<S>>::decode_value(value)?,
        ))
    }

    fn seek_to_first(&mut self) -> bool {
        let seek_key = rocksdb::SeekKey::Start;
        self.db_iter.seek(seek_key)
    }

    fn is_in_valid_range(&self) -> bool {
        self.db_iter.valid()
    }
}

impl<'a, S> Iterator for SchemaIterator<'a, S>
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

define_schema!(EdgeSchema, Edge, Weight, "Edge");
pub type Weight = u64;
impl KeyCodec<EdgeSchema> for Edge {
    fn encode_key(&self) -> Result<Vec<u8>> {
        lcs::to_bytes(self).map_err(Into::into)
    }

    fn decode_key(data: &[u8]) -> Result<Self> {
        lcs::from_bytes(data).map_err(Into::into)
    }
}

impl ValueCodec<EdgeSchema> for Weight {
    fn encode_value(&self) -> Result<Vec<u8>> {
        lcs::to_bytes(self).map_err(Into::into)
    }

    fn decode_value(data: &[u8]) -> Result<Self> {
        lcs::from_bytes(data).map_err(Into::into)
    }
}

define_schema!(VertexSchema, AccountAddress, Vertex, "Vertex");
impl KeyCodec<VertexSchema> for AccountAddress {
    fn encode_key(&self) -> Result<Vec<u8>> {
        lcs::to_bytes(self).map_err(Into::into)
    }

    fn decode_key(data: &[u8]) -> Result<Self> {
        lcs::from_bytes(data).map_err(Into::into)
    }
}

impl ValueCodec<VertexSchema> for Vertex {
    fn encode_value(&self) -> Result<Vec<u8>> {
        lcs::to_bytes(self).map_err(Into::into)
    }

    fn decode_value(data: &[u8]) -> Result<Self> {
        lcs::from_bytes(data).map_err(Into::into)
    }
}
