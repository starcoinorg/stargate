// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::rocksdb_utils::FixedPrefixSliceTransform;
use libra_tools::tempdir::TempPath;
//use libra_logger::prelude::*;
use rocksdb::{ColumnFamilyOptions, DBOptions, ReadOptions, SeekKey, Writable};
use std::iter::Iterator;

#[test]
fn test_rocksdb_prefix_seek() {
    libra_logger::try_init_for_testing();
    let tmp_dir = TempPath::new();
    let mut db_opts = DBOptions::default();
    db_opts.create_if_missing(true);
    let cfs = vec![("default", default_column_family_options())];
    let db = rocksdb::DB::open_cf(db_opts, tmp_dir.path().to_str().unwrap(), cfs).unwrap();
    let data = [
        ([0u8, 0, 0, 0], b"111"),
        ([0, 0, 0, 1], b"222"),
        ([0, 1, 0, 1], b"333"),
        ([0, 1, 1, 1], b"444"),
        ([0, 1, 2, 1], b"555"),
        ([0, 2, 0, 0], b"666"),
        ([2, 0, 0, 0], b"777"),
        ([2, 2, 2, 2], b"888"),
    ];
    for (key, value) in &data {
        assert!(db.put(key, *value).is_ok());
    }

    // prefix read, same as start
    let mut iter = db.iter_opt(prefix_read_options(true));

    assert!(iter.seek([0u8, 1, 1].as_ref().into()));
    assert_eq!(2, iter.count());
    assert!(!iter.valid(), "iter is not valid now");

    assert!(iter.seek([0u8, 1].as_ref().into()));
    assert_eq!(3, iter.count());
    assert!(!iter.valid(), "iter is not valid now");

    assert!(
        !iter.seek_for_prev([2, 0].as_ref().into()),
        "seek for prev should not work"
    );
    assert!(!iter.seek(SeekKey::End), "seek to end should not valid");

    let mut iter = db.iter_opt(prefix_read_options(false));
    assert!(iter.seek([0u8, 1, 1].as_ref().into()));
    assert_eq!(5, iter.count());
    assert!(!iter.valid());
    assert!(
        iter.seek_for_prev([2, 0].as_ref().into()),
        "seek for prev should be valid"
    );
    assert_eq!([0, 2, 0, 0], iter.key());
}

fn prefix_read_options(prefix_same_as_start: bool) -> ReadOptions {
    let mut opts = ReadOptions::default();
    opts.set_prefix_same_as_start(prefix_same_as_start);
    opts
}

fn default_column_family_options() -> rocksdb::ColumnFamilyOptions {
    let mut cfo = ColumnFamilyOptions::default();
    cfo.set_prefix_extractor(
        "FixedPrefixSliceTransform",
        Box::new(FixedPrefixSliceTransform::new(2)),
    )
    .unwrap();
    cfo
}
