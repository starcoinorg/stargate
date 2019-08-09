use super::*;
use crate::change_set::{ChangeSet, ChangeSetMut, ChangeOp};
use types::access_path::{AccessPath, Accesses, Field};
use types::language_storage::ResourceKey;
use types::account_address::AccountAddress;
use types::account_config::account_struct_tag;

#[test]
fn test_change_set_merge(){
    let account_address = AccountAddress::random();
    let resource_key = ResourceKey::new(account_address, account_struct_tag());
    let mut accesses = Accesses::new(Field::new("balance"));
    accesses.append(&mut Accesses::new(Field::new("value")));
    let access_path = AccessPath::resource_access_path(&resource_key, &accesses);
    let change_set0 = ChangeSetMut::new(vec![(access_path.clone(), ChangeOp::Plus(100))]);
    let change_set1 = ChangeSetMut::new(vec![(access_path.clone(), ChangeOp::Plus(100))]);
    let change_set2 = ChangeSetMut::merge(change_set0, change_set1).unwrap();
    if let (_, ChangeOp::Plus(value)) = change_set2[0] {
        assert_eq!(200, value);
        println!("merged value:{}", value)
    }else{
        debug_assert!(true, "unexpect change result.")
    }
}