use super::*;

#[test]
fn test_local_state_storage(){
    let client = Box::new(chain_client::ChainClientFacade::new());
    let storage = LocalStateStorage::new(AccountAddress::random(),client);

}