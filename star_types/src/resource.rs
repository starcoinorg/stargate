use std::ops::Deref;

use itertools::Itertools;

use canonical_serialization::{CanonicalDeserialize, CanonicalDeserializer, CanonicalSerialize, CanonicalSerializer, SimpleDeserializer, SimpleSerializer};
use failure::prelude::*;
use types::access_path::{Accesses};
use types::account_config::{account_struct_tag, AccountResource};
use types::language_storage::StructTag;
use vm_runtime_types::{loaded_data::struct_def::StructDef, value::MutVal};
use vm_runtime_types::loaded_data::types::Type;
use vm_runtime_types::value::Value;

use crate::change_set::{ChangeOp, ChangeSet, FieldChanges};

#[derive(Clone, Debug)]
pub struct Resource {
    tag: StructTag,
    fields: Vec<MutVal>,
}

impl Resource {
    pub fn new(tag: StructTag, fields: Vec<MutVal>) -> Self {
        //TODO check def and fields
        Self {
            tag,
            fields,
        }
    }

    pub fn new_from_account_resource(account_resource: AccountResource) -> Self {
        //this serialize and decode should never fail, so use unwrap.
        let out: Vec<u8> = SimpleSerializer::serialize(&account_resource).unwrap();
        Self::decode(account_struct_tag(), get_account_struct_def(), &out).expect("decode fail.")
    }

    pub fn decode(tag: StructTag, def: StructDef, bytes: &Vec<u8>) -> Result<Self> {
        let value = Value::simple_deserialize(bytes, def).map_err(|vm_error| format_err!("decode resource fail:{:?}", vm_error))?;
        if let Value::Struct(fields) = value {
            Ok(Self {
                tag,
                fields,
            })
        } else {
            Err(format_err!("decode resource fail, expect struct but get:{:?}", value))
        }
    }

    pub fn encode(&self) -> Option<Vec<u8>> {
        Into::<Value>::into(self).simple_serialize()
    }


    pub fn diff(&self, other: Resource) -> Result<FieldChanges> {
        ensure!(self.tag == other.tag, "diff only support same type resource.");
        ensure!(self.fields.len() == other.fields.len(), "two resource's fields len should be same.");
        let mut changes = FieldChanges::empty();
        let it = self.fields.iter().zip(other.fields.iter());
        for (idx, (first_value, second_value)) in it.enumerate() {
            changes.append(&mut Self::diff_field(idx, first_value, second_value)?)
        }
        Ok(changes)
    }

    fn diff_field(idx: usize, first: &MutVal, second: &MutVal) -> Result<FieldChanges> {
        let mut changes = FieldChanges::empty();
        let mut accesses = Accesses::empty();
        accesses.add_index_to_back(idx as u64);
        match &*first.peek() {
            Value::U64(first_value) => if let Value::U64(second_value) = &*second.peek() {
                let change_op = if first_value == second_value {
                    ChangeOp::None
                } else if first_value > second_value {
                    ChangeOp::Minus(first_value - second_value)
                } else {
                    ChangeOp::Plus(second_value - first_value)
                };
                changes.push((accesses, change_op));
            } else {
                bail!("expect type {:?} but get {:?}", first, second);
            },
            Value::Struct(first_struct) => if let Value::Struct(second_struct) = &*second.peek() {
                for (field_idx, (first_value, second_value)) in first_struct.iter().zip(second_struct).enumerate() {
                    let mut field_changes = Self::diff_field(field_idx, first_value, second_value)?;
                    for (mut field_accesses, field_change_op) in field_changes {
                        let mut new_accesses = accesses.clone();
                        new_accesses.append(&mut field_accesses);
                        changes.push((new_accesses, field_change_op));
                    }
                }
            } else {
                bail!("expect type {:?} but get {:?}", first, second);
            },
            Value::ByteArray(first_value) => if let Value::ByteArray(second_value) = &*second.peek() {
                let change_op = if first_value == second_value {
                    ChangeOp::None
                } else {
                    ChangeOp::Update(second_value.as_bytes().to_vec())
                };
                changes.push((accesses, change_op));
            } else {
                bail!("expect type {:?} but get {:?}", first, second);
            },
            Value::Address(first_value) => if let Value::Address(second_value) = &*second.peek() {
                let change_op = if first_value == second_value {
                    ChangeOp::None
                } else {
                    ChangeOp::Update(second_value.to_vec())
                };
                changes.push((accesses, change_op));
            } else {
                bail!("expect type {:?} but get {:?}", first, second);
            },
            Value::Bool(first_value) => if let Value::Bool(second_value) = &*second.peek() {
                let change_op = if first_value == second_value {
                    ChangeOp::None
                } else {
                    let byte: u8 = if *second_value { 1 } else { 0 };
                    ChangeOp::Update(vec![byte])
                };
                changes.push((accesses, change_op));
            } else {
                bail!("expect type {:?} but get {:?}", first, second);
            },
            Value::String(first_value) => if let Value::String(second_value) = &*second.peek() {
                let change_op = if first_value == second_value {
                    ChangeOp::None
                } else {
                    ChangeOp::Update(second_value.clone().into_bytes())
                };
                changes.push((accesses, change_op));
            } else {
                bail!("expect type {:?} but get {:?}", first, second);
            },
        }
        Ok(changes)
    }
}

impl Into<Value> for Resource {
    fn into(self) -> Value {
        (&self).into()
    }
}

impl Into<Value> for &Resource {
    fn into(self) -> Value {
        Value::Struct(self.fields.clone())
    }
}


fn get_account_struct_def() -> StructDef {
    let int_type = Type::U64;
    let byte_array_type = Type::ByteArray;
    let coin = Type::Struct(StructDef::new(vec![int_type.clone()]));
    StructDef::new(vec![
        byte_array_type,
        coin,
        Type::Bool,
        int_type.clone(),
        int_type.clone(),
        int_type.clone(),
    ])
}