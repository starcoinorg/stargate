use std::ops::Deref;

use itertools::Itertools;

use canonical_serialization::{CanonicalDeserialize, CanonicalDeserializer, CanonicalSerialize, CanonicalSerializer, SimpleDeserializer, SimpleSerializer};
use failure::prelude::*;
use logger::prelude::*;
use types::access_path::{Access, Accesses};
use types::account_address::AccountAddress;
use types::account_config::{account_struct_tag, AccountResource, COIN_MODULE_NAME, core_code_address, COIN_STRUCT_NAME};
use types::byte_array::ByteArray;
use types::language_storage::StructTag;
use vm_runtime_types::{loaded_data::struct_def::StructDef, value::MutVal};
use vm_runtime_types::loaded_data::types::Type;
use vm_runtime_types::value::{Reference, Value};

use crate::change_set::{Changeable, ChangeOp, ChangeSet, FieldChanges};

#[derive(Clone, Debug)]
pub struct Resource {
    fields: MutVal,
}

impl Resource {
    pub fn new(fields: Vec<MutVal>) -> Self {
        //TODO check def and fields
        Self {
            fields: MutVal::new(Value::Struct(fields)),
        }
    }

    /// Create a empty struct, field with default value.
    pub fn empty(def: &StructDef) -> Self {
        Self::new(Self::new_fields(&def))
    }

    fn new_fields(def: &StructDef) -> Vec<MutVal> {
        let mut fields = vec![];
        for field_type in def.field_definitions() {
            fields.push(MutVal::new(Self::new_field(field_type)));
        }
        fields
    }

    fn new_field(field_type: &Type) -> Value {
        match field_type {
            Type::Bool => Value::Bool(false),
            Type::ByteArray => Value::ByteArray(ByteArray::new(vec![])),
            Type::String => Value::String(String::new()),
            Type::Address => Value::Address(AccountAddress::default()),
            Type::U64 => Value::U64(0),
            Type::Struct(struct_def) => {
                Value::Struct(Self::new_fields(struct_def))
            }
            _ => panic!("Unsupported field type: {:?}", field_type)
        }
    }

    pub fn from_changes(changes: &FieldChanges, def: &StructDef) -> Self {
        let mut empty_resource = Self::empty(def);
        empty_resource.apply_changes(changes);
        empty_resource
    }

    pub fn fields(&self) -> Vec<MutVal> {
        if let Value::Struct(fields) = &*self.fields.peek() {
            //TODO optimize, not clone.
            fields.clone()
        } else {
            panic!("resource must be struct.")
        }
    }

    pub fn len(&self) -> usize {
        self.fields().len()
    }

    pub fn new_from_account_resource(account_resource: AccountResource) -> Self {
        //this serialize and decode should never fail, so use unwrap.
        let out: Vec<u8> = SimpleSerializer::serialize(&account_resource).unwrap();
        Self::decode(get_account_struct_def(), &out).expect("decode fail.")
    }

    pub fn decode(def: StructDef, bytes: &[u8]) -> Result<Self> {
        let value = Value::simple_deserialize(bytes, def).map_err(|vm_error| format_err!("decode resource fail:{:?}", vm_error))?;
        if let Value::Struct(fields) = value {
            Ok(Self::new(
                fields,
            ))
        } else {
            Err(format_err!("decode resource fail, expect struct but get:{:?}", value))
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        Into::<Value>::into(self).simple_serialize().expect("serialize should not fail.")
    }


    pub fn diff(&self, other: &Resource) -> Result<FieldChanges> {
        //ensure!(self.tag == other.tag, "diff only support same type resource.");
        ensure!(self.len() == other.len(), "two resource's fields len should be same.");
        let mut changes = FieldChanges::empty();
        let self_fields = self.fields();
        let other_fields = other.fields();
        let it = self_fields.iter().zip(other_fields.iter());
        for (idx, (first_value, second_value)) in it.enumerate() {
            changes.append(&mut Self::diff_field(idx, first_value, second_value)?)
        }
        changes.filter_none();
        debug!("diff resource {:#?} with {:#?}", self, other);
        debug!("diff result: {:#?}", changes);
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

    fn borrow_field(&self, accesses: &Accesses) -> Result<MutVal> {
        //TODO optimize, not use clone.
        let mut value = self.fields.borrow_field(accesses.first().index().unwrap() as u32).ok_or(format_err!("Can not find field by access {:?}", accesses))?;
        for access in accesses.range(1, accesses.len()).iter() {
            if let Access::Index(idx) = access {
                value = value.borrow_field(*idx as u32).ok_or(format_err!("can not find field by accesses {:?}", accesses))?;
            } else {
                bail!("Only support access by index currently")
            }
        }
        Ok(value)
    }

    pub fn apply_changes(&mut self, field_changes: &FieldChanges) -> Result<()> {
        for (accesses, change_op) in field_changes {
            let mut val = self.borrow_field(accesses)?;
            val.apply_change(change_op.clone());
        }
        Ok(())
    }

    pub fn to_changes(&self) -> FieldChanges {
        let mut changes = FieldChanges::empty();
        for (idx, field) in self.fields().iter().enumerate() {
            changes.append(&mut Self::field_to_changes(idx, field));
        }
        changes
    }

    fn field_to_changes(idx: usize, field: &MutVal) -> FieldChanges {
        let mut accesses = Accesses::new_with_index(idx as u64);
        let mut changes = FieldChanges::empty();
        match &*field.peek() {
            Value::U64(value) => {
                changes.push((accesses, ChangeOp::Plus(*value)))
            }
            Value::Struct(values) => {
                for (idx, sub_field) in values.iter().enumerate() {
                    let sub_changes = Self::field_to_changes(idx, sub_field);
                    for (mut field_accesses, field_change_op) in sub_changes {
                        let mut new_accesses = accesses.clone();
                        new_accesses.append(&mut field_accesses);
                        changes.push((new_accesses, field_change_op));
                    }
                }
            }
            Value::Address(value) => {
                changes.push((accesses, ChangeOp::Update(value.to_vec())));
            }
            Value::String(value) => {
                changes.push((accesses, ChangeOp::Update(value.clone().into_bytes())));
            }
            Value::Bool(value) => {
                let byte: u8 = if *value { 1 } else { 0 };
                changes.push((accesses, ChangeOp::Update(vec![byte])));
            }
            Value::ByteArray(value) => {
                changes.push((accesses, ChangeOp::Update(value.as_bytes().to_vec())))
            }
        }
        changes
    }
}

impl Into<Value> for Resource {
    fn into(self) -> Value {
        (&self).into()
    }
}

impl Into<Value> for &Resource {
    fn into(self) -> Value {
        self.fields.peek().clone()
    }
}

impl Into<FieldChanges> for &Resource {
    fn into(self) -> FieldChanges {
        self.to_changes()
    }
}

impl std::cmp::PartialEq for Resource {
    fn eq(&self, other: &Self) -> bool {
        //TODO optimize
        self.encode() == other.encode()
    }
}

pub fn get_account_struct_def() -> StructDef {
    let int_type = Type::U64;
    let byte_array_type = Type::ByteArray;
    let coin = Type::Struct(get_coin_struct_def());

    let event_handle = Type::Struct(get_event_handle_struct_def());

    StructDef::new(vec![
        byte_array_type,
        coin,
        Type::Bool,
        event_handle.clone(),
        event_handle.clone(),
        int_type.clone(),
    ])
}

pub fn get_coin_struct_def() -> StructDef {
    let int_type = Type::U64;
    StructDef::new(vec![int_type.clone()])
}

pub fn get_market_cap_struct_tag() -> StructTag{
    StructTag {
        module: COIN_MODULE_NAME.to_string(),
        name: "MarketCap".to_string(),
        address: core_code_address(),
        type_params: vec![],
    }
}

pub fn get_market_cap_struct_def() -> StructDef {
    let int_type = Type::U64;
    StructDef::new(vec![int_type.clone()])
}

pub fn get_mint_capability_struct_tag() -> StructTag{
    StructTag {
        module: COIN_MODULE_NAME.to_string(),
        name: "MintCapability".to_string(),
        address: core_code_address(),
        type_params: vec![],
    }
}

pub fn get_mint_capability_struct_def() -> StructDef {
    StructDef::new(vec![])
}

pub fn get_event_handle_struct_tag() -> StructTag {
    StructTag {
        module: "Event".to_string(),
        name: "Handle".to_string(),
        address: core_code_address(),
        type_params: vec![],
    }
}

pub fn get_event_handle_struct_def() -> StructDef {
    StructDef::new(vec![
        Type::U64,
        Type::ByteArray,
    ])
}

pub fn get_event_handle_id_generator_tag() -> StructTag {
    StructTag {
        module: "Event".to_string(),
        name: "HandleIdGenerator".to_string(),
        address: core_code_address(),
        type_params: vec![],
    }
}

pub fn get_event_handle_id_generator_def() -> StructDef {
    StructDef::new(vec![
        Type::U64,
    ])
}