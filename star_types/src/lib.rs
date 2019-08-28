#![feature(custom_attribute)]
pub mod account_resource_ext;
pub mod channel;
pub mod message;
pub mod offchain_transaction;
pub mod proto;
pub mod resource;
pub mod system_event;

#[cfg(test)]
mod resource_test;
pub mod transaction_output_helper;
pub mod change_set;
#[cfg(test)]
mod change_set_test;
pub mod resource_value;
pub mod resource_value_serializer;
pub mod resource_type;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
