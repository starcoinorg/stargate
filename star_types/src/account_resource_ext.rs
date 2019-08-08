use canonical_serialization::{SimpleDeserializer, SimpleSerializer};
use failure::prelude::*;
use std::convert::{TryFrom, TryInto};
use types::account_config::AccountResource;

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
