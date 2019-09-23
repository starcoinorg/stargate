#![feature(custom_attribute)]

pub mod account_resource_ext;
pub mod message;
pub mod channel_transaction;
#[cfg(test)]
mod channel_transaction_test;
pub mod proto;
pub mod resource;
pub mod system_event;
pub mod watch_tx_data;
pub mod sg_error;

#[cfg(test)]
mod resource_test;
pub mod transaction_output_helper;
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
