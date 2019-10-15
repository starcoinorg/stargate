use canonical_serialization::{SimpleDeserializer, SimpleSerializer};
use failure::prelude::*;
use libra_types::{
    account_address::AccountAddress, account_config::AccountResource, event::EventHandle,
};

pub fn to_bytes(account_resource: &AccountResource) -> Result<Vec<u8>> {
    SimpleSerializer::serialize(account_resource)
}

pub fn from_bytes(value: &Vec<u8>) -> Result<AccountResource> {
    SimpleDeserializer::deserialize(value.as_slice())
}

pub fn new_account_for_test(account_address: AccountAddress, balance: u64) -> AccountResource {
    let event_handle = EventHandle::new_from_address(&account_address, 0);
    AccountResource::new(
        balance,
        1,
        libra_types::byte_array::ByteArray::new(vec![]),
        false,
        false,
        event_handle.clone(),
        event_handle.clone(),
    )
}
