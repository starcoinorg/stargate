use super::*;

#[test]
fn test_local_state_storage(){
    let client = Arc::new(chain_client::RpcChainClient::new("localhost", 1234));
    let storage = LocalStateStorage::new(AccountAddress::random(),client);

}