use canonical_serialization::{SimpleDeserializer, SimpleSerializer};
use failure::prelude::*;
use std::convert::{TryFrom, TryInto};
use types::account_config::{AccountResource, EventHandle};
use types::account_address::AccountAddress;

//impl TryFrom<Vec<u8>> for AccountResource{
//    type Error = failure::Error;
//
//    fn try_from(value: Vec<u8>) -> Result<Self> {
//        SimpleDeserializer::deserialize(value.as_slice())
//    }
//}
//
//impl TryInto<Vec<u8>> for &AccountResource{
//    type Error = failure::Error;
//
//    fn try_into(self) -> Result<Vec<u8>> {
//        SimpleSerializer::serialize(self)
//    }
//}

pub fn to_bytes(account_resource: &AccountResource) -> Result<Vec<u8>> {
    SimpleSerializer::serialize(account_resource)
}

pub fn from_bytes(value: &Vec<u8>) -> Result<AccountResource> {
    SimpleDeserializer::deserialize(value.as_slice())
}

pub fn new_account_for_test(balance: u64) -> AccountResource{
    let account_address = AccountAddress::random();
    let event_handle = EventHandle::new_from_address(&account_address, 0);
    AccountResource::new(100, 1, types::byte_array::ByteArray::new(vec![]), false,
                         event_handle.clone(), event_handle.clone())
}