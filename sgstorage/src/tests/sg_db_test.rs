//use crate::channel_state_store::{ChannelState, ChannelStateStore};
//use crate::schema_db::SchemaDB;
//use crate::sg_db::SgDB;
//use crypto::hash::CryptoHash;
//use crypto::HashValue;
//use failure::Result;
//use libra_tools::tempdir::TempPath;
//use libra_types::account_address::AccountAddress;
//use libra_types::account_state_blob::AccountStateBlob;
//use libra_types::transaction::Version;
//use schemadb::SchemaBatch;
//use std::collections::HashMap;
//use std::sync::Arc;
//
//#[test]
//fn test_create_db() {
//    logger::try_init_for_testing();
//    let tmp_dir = TempPath::new();
//    let sender_address = AccountAddress::random();
//    let sg_db = Arc::new(SgDB::open(sender_address, &tmp_dir));
//}
