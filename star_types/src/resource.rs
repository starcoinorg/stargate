use std::ops::Deref;

use itertools::Itertools;

use canonical_serialization::{CanonicalDeserialize, CanonicalDeserializer, CanonicalSerialize, CanonicalSerializer, SimpleDeserializer, SimpleSerializer};
use failure::prelude::*;
use logger::prelude::*;
use types::access_path::{Access, Accesses};
use types::account_address::AccountAddress;
use types::account_config::{account_struct_tag, AccountResource, COIN_MODULE_NAME, core_code_address, COIN_STRUCT_NAME, coin_struct_tag};
use types::byte_array::ByteArray;
use types::language_storage::StructTag;
use crate::{
    resource_value::{ResourceValue,MutResourceVal},
    resource_type::{resource_types::ResourceType, resource_def::ResourceDef},
    change_set::{Changeable, ChangeOp, ChangeSet, FieldChanges},
};

#[derive(Clone, Debug)]
pub struct Resource {
    fields: MutResourceVal,
}

impl Resource {
    pub fn new(tag: StructTag, fields: Vec<MutResourceVal>) -> Self {
        //TODO check def and fields
        Self {
            fields: MutResourceVal::new(ResourceValue::Resource(tag, fields)),
        }
    }

    pub fn new_with_value(fields: ResourceValue) -> Result<Self>{
        if !fields.is_resource() {
            bail!("expect resource but get:{:?}", fields);
        }
        Ok(Self{
            fields:MutResourceVal::new(fields)
        })
    }

    /// Create a empty struct, field with default value.
    pub fn empty(tag: StructTag, def: &ResourceDef) -> Self {
        Self::new(tag, Self::new_fields(&def))
    }

    fn new_fields(def: &ResourceDef) -> Vec<MutResourceVal> {
        let mut fields = vec![];
        for field_type in def.field_definitions() {
            fields.push(MutResourceVal::new(Self::new_field(field_type)));
        }
        fields
    }

    fn new_field(field_type: &ResourceType) -> ResourceValue {
        match field_type {
            ResourceType::Bool => ResourceValue::Bool(false),
            ResourceType::ByteArray => ResourceValue::ByteArray(ByteArray::new(vec![])),
            ResourceType::String => ResourceValue::String(String::new()),
            ResourceType::Address => ResourceValue::Address(AccountAddress::default()),
            ResourceType::U64 => ResourceValue::U64(0),
            ResourceType::Resource(struct_tag, struct_def) => {
                ResourceValue::Resource(struct_tag.clone(), Self::new_fields(struct_def))
            }
            _ => panic!("Unsupported field type: {:?}", field_type)
        }
    }

    pub fn from_changes(changes: &FieldChanges, tag: StructTag, def: &ResourceDef) -> Self {
        let mut empty_resource = Self::empty(tag,def);
        empty_resource.apply_changes(changes);
        empty_resource
    }

    /// Check current resource is asset resource.
    /// if a resource only contains a u64 field, it is considered an asset.
    /// TODO add a asset type tag to resource def
    pub fn is_asset(&self) -> bool{
        if self.fields_len() == 1 {
            return match *self.field(0).peek() {
                ResourceValue::U64(_) => true,
                _ => false,
            }
        }
        return false
    }

    pub fn fields(&self) -> Vec<MutResourceVal> {
        if let ResourceValue::Resource(_, fields) = &*self.fields.peek() {
            //TODO optimize, not clone.
            fields.clone()
        } else {
            panic!("resource must be struct.")
        }
    }

    pub fn fields_len(&self) -> usize {
        self.fields().len()
    }

    pub fn field(&self, idx: usize) -> MutResourceVal {
        if let ResourceValue::Resource(_, fields) = &*self.fields.peek() {
            fields[idx].clone()
        } else {
            panic!("resource must be struct.")
        }
    }

    pub fn new_from_account_resource(account_resource: AccountResource) -> Self {
        //this serialize and decode should never fail, so use unwrap.
        let out: Vec<u8> = SimpleSerializer::serialize(&account_resource).unwrap();
        Self::decode(account_struct_tag(), get_account_struct_def(), &out).expect("decode fail.")
    }

    pub fn decode(tag: StructTag, def: ResourceDef, bytes: &[u8]) -> Result<Self> {
        let value = ResourceValue::simple_deserialize(bytes, tag,def).map_err(|vm_error| format_err!("decode resource fail:{:?}", vm_error))?;
        Self::new_with_value(value)
    }

    pub fn encode(&self) -> Vec<u8> {
        Into::<ResourceValue>::into(self).simple_serialize().expect("serialize should not fail.")
    }


    pub fn diff(&self, other: &Resource) -> Result<FieldChanges> {
        //ensure!(self.tag == other.tag, "diff only support same type resource.");
        ensure!(self.fields_len() == other.fields_len(), "two resource's fields len should be same.");
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

    fn diff_field(idx: usize, first: &MutResourceVal, second: &MutResourceVal) -> Result<FieldChanges> {
        let mut changes = FieldChanges::empty();
        let mut accesses = Accesses::empty();
        accesses.add_index_to_back(idx as u64);
        match &*first.peek() {
            ResourceValue::U64(first_value) => if let ResourceValue::U64(second_value) = &*second.peek() {
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
            ResourceValue::Resource(first_tag, first_struct) => if let ResourceValue::Resource(second_tag, second_struct) = &*second.peek() {
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
            ResourceValue::ByteArray(first_value) => if let ResourceValue::ByteArray(second_value) = &*second.peek() {
                let change_op = if first_value == second_value {
                    ChangeOp::None
                } else {
                    ChangeOp::Update(second_value.as_bytes().to_vec())
                };
                changes.push((accesses, change_op));
            } else {
                bail!("expect type {:?} but get {:?}", first, second);
            },
            ResourceValue::Address(first_value) => if let ResourceValue::Address(second_value) = &*second.peek() {
                let change_op = if first_value == second_value {
                    ChangeOp::None
                } else {
                    ChangeOp::Update(second_value.to_vec())
                };
                changes.push((accesses, change_op));
            } else {
                bail!("expect type {:?} but get {:?}", first, second);
            },
            ResourceValue::Bool(first_value) => if let ResourceValue::Bool(second_value) = &*second.peek() {
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
            ResourceValue::String(first_value) => if let ResourceValue::String(second_value) = &*second.peek() {
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

    fn borrow_field(&self, accesses: &Accesses) -> Result<MutResourceVal> {
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

    fn field_to_changes(idx: usize, field: &MutResourceVal) -> FieldChanges {
        let mut accesses = Accesses::new_with_index(idx as u64);
        let mut changes = FieldChanges::empty();
        match &*field.peek() {
            ResourceValue::U64(value) => {
                changes.push((accesses, ChangeOp::Plus(*value)))
            }
            ResourceValue::Resource(tag, values) => {
                for (idx, sub_field) in values.iter().enumerate() {
                    let sub_changes = Self::field_to_changes(idx, sub_field);
                    for (mut field_accesses, field_change_op) in sub_changes {
                        let mut new_accesses = accesses.clone();
                        new_accesses.append(&mut field_accesses);
                        changes.push((new_accesses, field_change_op));
                    }
                }
            }
            ResourceValue::Address(value) => {
                changes.push((accesses, ChangeOp::Update(value.to_vec())));
            }
            ResourceValue::String(value) => {
                changes.push((accesses, ChangeOp::Update(value.clone().into_bytes())));
            }
            ResourceValue::Bool(value) => {
                let byte: u8 = if *value { 1 } else { 0 };
                changes.push((accesses, ChangeOp::Update(vec![byte])));
            }
            ResourceValue::ByteArray(value) => {
                changes.push((accesses, ChangeOp::Update(value.as_bytes().to_vec())))
            }
        }
        changes
    }
}

impl Into<ResourceValue> for Resource {
    fn into(self) -> ResourceValue {
        (&self).into()
    }
}

impl Into<ResourceValue> for &Resource {
    fn into(self) -> ResourceValue {
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

pub fn get_account_struct_def() -> ResourceDef {
    let int_type = ResourceType::U64;
    let byte_array_type = ResourceType::ByteArray;
    let coin = ResourceType::Resource(coin_struct_tag(), get_coin_struct_def());

    let event_handle = ResourceType::Resource(get_event_handle_struct_tag(), get_event_handle_struct_def());

    ResourceDef::new(vec![
        byte_array_type,
        coin,
        ResourceType::Bool,
        event_handle.clone(),
        event_handle.clone(),
        int_type.clone(),
    ])
}

pub fn get_coin_struct_def() -> ResourceDef {
    let int_type = ResourceType::U64;
    ResourceDef::new(vec![int_type.clone()])
}

pub fn get_market_cap_struct_tag() -> StructTag{
    StructTag {
        module: COIN_MODULE_NAME.to_string(),
        name: "MarketCap".to_string(),
        address: core_code_address(),
        type_params: vec![],
    }
}

pub fn get_market_cap_struct_def() -> ResourceDef {
    let int_type = ResourceType::U64;
    ResourceDef::new(vec![int_type.clone()])
}

pub fn get_mint_capability_struct_tag() -> StructTag{
    StructTag {
        module: COIN_MODULE_NAME.to_string(),
        name: "MintCapability".to_string(),
        address: core_code_address(),
        type_params: vec![],
    }
}

pub fn get_mint_capability_struct_def() -> ResourceDef {
    ResourceDef::new(vec![])
}

pub fn get_event_handle_struct_tag() -> StructTag {
    StructTag {
        module: "Event".to_string(),
        name: "Handle".to_string(),
        address: core_code_address(),
        type_params: vec![],
    }
}

pub fn get_event_handle_struct_def() -> ResourceDef {
    ResourceDef::new(vec![
        ResourceType::U64,
        ResourceType::ByteArray,
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

pub fn get_event_handle_id_generator_def() -> ResourceDef {
    ResourceDef::new(vec![
        ResourceType::U64,
    ])
}

pub fn get_block_module_tag() -> StructTag {
    StructTag {
        module: "Block".to_string(),
        name: "T".to_string(),
        address: core_code_address(),
        type_params: vec![]
    }
}

pub fn get_block_module_def() -> ResourceDef {
    ResourceDef::new(vec![
        ResourceType::U64,
    ])
}