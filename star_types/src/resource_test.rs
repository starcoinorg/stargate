use super::*;
use crate::resource::*;
use types::account_config::AccountResource;
use canonical_serialization::{SimpleSerializer, CanonicalSerialize};
use hex;

#[test]
fn test_resource(){
    let account_resource = AccountResource::new(100,1,types::byte_array::ByteArray::new(vec![]),0,0,false);
    let mut serializer = SimpleSerializer::new();
    account_resource.serialize(&mut serializer).unwrap();
    let out: Vec<u8> = serializer.get_output();
    println!("{:#?}", hex::encode(out));
}