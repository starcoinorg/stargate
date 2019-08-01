use types::account_address::AccountAddress;

use crate::access_path::*;

#[test]
fn test_access_path() {
    let access_path = AccessPath::new_for_account_resource(AccountAddress::random());
    println!("{:#?}", access_path);
    let access_path2 = access_path.into_libra_access_path();
    println!("{:#?}", access_path2);
}