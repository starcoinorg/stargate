use failure::prelude::*;
use schemadb::schema::{Schema, SeekKeyCodec};
use schemadb::{ReadOptions, SchemaBatch};

pub trait SchemaDB {
    fn get<S: Schema>(&self, schema_key: &S::Key) -> Result<Option<S::Value>>
    where
        S::Key: Clone;
    fn put<S: Schema>(&self, key: &S::Key, value: &S::Value) -> Result<()>;
    /// Delete all keys in range [begin, end).
    /// `SK` has to be an explict type parameter since
    /// https://github.com/rust-lang/rust/issues/44721
    fn range_delete<S, SK>(&self, begin: &SK, end: &SK) -> Result<()>
    where
        S: Schema,
        SK: SeekKeyCodec<S>;

    fn iter<'a, S: Schema + 'static>(
        &'a self,
        opts: ReadOptions,
    ) -> Result<Box<dyn SchemaIterator<S> + 'a>>;

    fn write_schemas(&self, batch: SchemaBatch) -> Result<()>;
}

pub trait SchemaIterator<S: Schema>: Iterator<Item = Result<(S::Key, S::Value)>> {
    /// Seeks to the first key.
    fn seek_to_first(&mut self) -> bool;

    /// Seeks to the lasy key.
    fn seek_to_last(&mut self) -> bool;

    /// Seeks to the first key whose binary representation is equal to or greater than that of the
    /// `seek_key`.
    fn seek(&mut self, seek_key: &S::Key) -> Result<bool>;

    /// Seeks to the last key whose binary representation is less than or equal to that of the
    /// `seek_key`.
    ///
    /// See example in [`RocksDB doc`](https://github.com/facebook/rocksdb/wiki/SeekForPrev).
    fn seek_for_prev(&mut self, seek_key: &S::Key) -> Result<bool>;
}
