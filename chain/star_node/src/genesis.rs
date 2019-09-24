use vm_genesis::{encode_genesis_transaction, GENESIS_KEYPAIR};
use std::fs::create_dir_all;
use std::fs::File;
use proto_conv::{IntoProto, IntoProtoBytes};
use std::io::Write;
use std::path::Path;
use tools::tempdir::TempPath;
use logger::prelude::*;

pub fn genesis_blob() -> String {
    let genesis_checked_txn = encode_genesis_transaction(&GENESIS_KEYPAIR.0, GENESIS_KEYPAIR.1.clone());
    let genesis_txn = genesis_checked_txn.into_inner();
//    let tmp_dir = TempPath::new();
//    tmp_dir.create_as_dir().unwrap();
//    let path = tmp_dir.path().display();
    let path = "/tmp/data";
    let blob_path = Path::new(&path);
    if !blob_path.exists() {
        create_dir_all(blob_path).unwrap();
    }
    let file = format!("{}/{}", path, "genesis.blob");
    let mut genesis_file = File::create(Path::new(&file)).expect("open genesis file err.");
    genesis_file.write_all(genesis_txn.into_proto_bytes().expect("genesis_txn to bytes err.").as_slice()).expect("write genesis file err.");
    genesis_file.flush().unwrap();
    info!("genesis blob path: {}", file);
    file
}