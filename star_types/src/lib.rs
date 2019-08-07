pub mod offchain_transaction;
pub mod channel;
pub mod access_path;
#[cfg(test)]
mod access_path_test;
pub mod resource;
#[cfg(test)]
mod resource_test;
pub mod proto;
pub mod transaction_output_helper;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
