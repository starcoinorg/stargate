use types::access_path::{Accesses, AccessPath, DataPath};
use types::account_address::AccountAddress;
use types::account_config::account_struct_tag;
use types::language_storage::ResourceKey;

use crate::change_set::{ChangeOp, Changes, ChangeSet, ChangeSetMut, FieldChanges, Changeable};

use super::*;
use vm_runtime_types::value::{MutVal, Value, GlobalRef, Reference};

#[test]
fn test_change_op_merge_plus() {
    let mut change_op0 = ChangeOp::Plus(100);
    let change_op1 = ChangeOp::Plus(100);
    let change_op2 = ChangeOp::merge(&change_op0, &change_op1).unwrap();
    assert_eq!(change_op2.as_plus().unwrap(), 200);

    change_op0.merge_with(&change_op1).unwrap();
    assert_eq!(change_op0.as_plus().unwrap(), 200);
}

#[test]
fn test_change_set_merge() {
    let account_address = AccountAddress::random();
    let resource_key = ResourceKey::new(account_address, account_struct_tag());
    let mut accesses = Accesses::empty();
    //balance filed
    accesses.add_index_to_back(1);
    //coin value filed.
    accesses.add_index_to_back(0);
    let access_path = AccessPath::on_chain_resource_access_path(&resource_key);

    let change_set0 = ChangeSetMut::new(vec![(access_path.clone(), Changes::Fields(FieldChanges::new(vec![(accesses.clone(), ChangeOp::Plus(100))])))]);
    let change_set1 = ChangeSetMut::new(vec![(access_path.clone(), Changes::Fields(FieldChanges::new(vec![(accesses.clone(), ChangeOp::Plus(110))])))]);
    let change_set2 = ChangeSetMut::merge(&change_set0, &change_set1).unwrap();
    let (access_path, changes) = &change_set2[0];
    println!("changes:{:#?}", changes);
    if let Changes::Fields(field_changes) = changes {
        if let (_, ChangeOp::Plus(value)) = field_changes[0] {
            assert_eq!(value, 210);
            println!("merged value:{}", value)
        } else {
            debug_assert!(true, "unexpect change result.")
        }
    } else {
        debug_assert!(true, "unexpect change result.")
    }
}

#[test]
fn test_apply_change(){
    let mut val = MutVal::new(Value::U64(100));
    val.apply_change(ChangeOp::Plus(100)).unwrap();

    assert_eq!(Into::<Option<u64>>::into(val.clone()).unwrap(), 200);
}