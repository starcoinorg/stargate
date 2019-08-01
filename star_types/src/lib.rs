pub mod offchain_transaction;
pub mod channel;
pub mod access_path;
pub mod resource;
#[cfg(test)]
mod resource_test;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
