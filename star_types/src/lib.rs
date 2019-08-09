#![feature(custom_attribute)]
pub mod access_path;
#[cfg(test)]
mod access_path_test;
pub mod account_resource_ext;
pub mod channel;
pub mod message;
pub mod offchain_transaction;
pub mod proto;
pub mod resource;
#[cfg(test)]
mod resource_test;
pub mod transaction_output_helper;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
