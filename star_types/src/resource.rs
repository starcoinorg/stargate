use std::ops::Deref;

use itertools::Itertools;
use protobuf::well_known_types::Struct;

use canonical_serialization::{CanonicalDeserialize, CanonicalDeserializer, CanonicalSerialize, CanonicalSerializer, SimpleDeserializer, SimpleSerializer};
use failure::prelude::*;
use logger::prelude::*;
use types::access_path::{Access, Accesses};
use types::account_address::AccountAddress;
use types::account_config::{account_struct_tag, AccountResource, coin_struct_tag, core_code_address, coin_module_name};
use types::byte_array::ByteArray;
use types::language_storage::StructTag;

use crate::{
    resource_type::{resource_def::ResourceDef, resource_types::ResourceType},
    resource_value::{MutResourceVal, ResourceValue},
};
use types::identifier::Identifier;

#[derive(Clone, Debug)]
pub struct Resource(StructTag, Vec<MutResourceVal>);

impl Resource {
    pub fn new(tag: StructTag, fields: Vec<MutResourceVal>) -> Self {
        //TODO check def and fields
        Self(tag, fields)
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
                ResourceValue::Resource(Resource::new(struct_tag.clone(), Self::new_fields(struct_def)))
            }
            _ => panic!("Unsupported field type: {:?}", field_type)
        }
    }

    /// Normal code should always know what type this value has. This is made available only for
    /// tests.
    #[allow(non_snake_case)]
    #[doc(hidden)]
    pub fn to_resource_def_FOR_TESTING(&self) -> ResourceDef {
        let fields = self.1
            .iter()
            .map(|mut_val| {
                let val = &*mut_val.peek();
                match val {
                    ResourceValue::Bool(_) => ResourceType::Bool,
                    ResourceValue::Address(_) => ResourceType::Address,
                    ResourceValue::U64(_) => ResourceType::U64,
                    ResourceValue::String(_) => ResourceType::String,
                    ResourceValue::ByteArray(_) => ResourceType::ByteArray,
                    ResourceValue::Resource(res) => ResourceType::Resource(res.tag().clone(), res.to_resource_def_FOR_TESTING()),
                }
            })
            .collect();
        ResourceDef::new(fields)
    }

    /// Check current resource is asset resource.
    /// TODO add a asset type tag to resource def
    pub fn is_asset(&self) -> bool {
        self.0 == coin_struct_tag()
    }

    /// if resource is asset, and return it balance
    pub fn asset_balance(&self) -> Option<u64> {
        if self.is_asset() {
            self.1.get(0).and_then(|field| Into::<Option<u64>>::into(field.clone()))
        } else {
            None
        }
    }

    pub fn visit_asset(&self, visitor: &dyn Fn(&StructTag, &Resource)) {
        if self.is_asset() {
            visitor(self.tag(), self)
        } else {
            for field in &self.1 {
                if let ResourceValue::Resource(res) = &*field.peek() {
                    res.visit_asset(visitor)
                }
            }
        }
    }

    pub fn tag(&self) -> &StructTag {
        &self.0
    }

    pub fn fields(&self) -> &Vec<MutResourceVal> {
        &self.1
    }

    pub fn len(&self) -> usize {
        self.1.len()
    }

    pub fn field(&self, idx: usize) -> Option<&MutResourceVal> {
        self.1.get(idx)
    }

    pub fn iter(&self) -> ::std::slice::Iter<'_, MutResourceVal> {
        self.1.iter()
    }

    pub fn new_from_account_resource(account_resource: AccountResource) -> Self {
        //this serialize and decode should never fail, so use unwrap.
        let out: Vec<u8> = SimpleSerializer::serialize(&account_resource).unwrap();
        Self::decode(account_struct_tag(), get_account_struct_def(), &out).expect("decode fail.")
    }

    pub fn decode(tag: StructTag, def: ResourceDef, bytes: &[u8]) -> Result<Self> {
        ResourceValue::simple_deserialize(bytes, tag, def).map_err(|vm_error| format_err!("decode resource fail:{:?}", vm_error))
    }

    pub fn encode(&self) -> Vec<u8> {
        Into::<ResourceValue>::into(self).simple_serialize().expect("serialize should not fail.")
    }

    fn borrow_field(&self, accesses: &Accesses) -> Result<MutResourceVal> {
        //TODO optimize, not use clone.
        let mut value = self.field(accesses.first().index().unwrap() as usize).map(MutResourceVal::shallow_clone).ok_or(format_err!("Can not find field by access {:?}", accesses))?;
        for access in accesses.range(1, accesses.len()).iter() {
            if let Access::Index(idx) = access {
                value = value.borrow_field(*idx as u32).ok_or(format_err!("can not find field by accesses {:?}", accesses))?;
            } else {
                bail!("Only support access by index currently")
            }
        }
        Ok(value)
    }
}

impl Into<ResourceValue> for Resource {
    fn into(self) -> ResourceValue {
        ResourceValue::Resource(self)
    }
}

impl Into<ResourceValue> for &Resource {
    fn into(self) -> ResourceValue {
        self.clone().into()
    }
}

impl std::cmp::PartialEq for Resource {
    fn eq(&self, other: &Self) -> bool {
        //TODO optimize
        self.encode() == other.encode()
    }
}

impl Into<(StructTag, Vec<MutResourceVal>)> for Resource {
    fn into(self) -> (StructTag, Vec<MutResourceVal>) {
        (self.0, self.1)
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

pub fn get_market_cap_struct_tag() -> StructTag {
    StructTag {
        module: coin_module_name().to_owned(),
        name: Identifier::new("MarketCap").unwrap(),
        address: core_code_address(),
        type_params: vec![],
    }
}

pub fn get_market_cap_struct_def() -> ResourceDef {
    let int_type = ResourceType::U64;
    ResourceDef::new(vec![int_type.clone()])
}

pub fn get_mint_capability_struct_tag() -> StructTag {
    StructTag {
        module: coin_module_name().to_owned(),
        name: Identifier::new("MintCapability").unwrap(),
        address: core_code_address(),
        type_params: vec![],
    }
}

pub fn get_mint_capability_struct_def() -> ResourceDef {
    ResourceDef::new(vec![])
}

pub fn get_event_handle_struct_tag() -> StructTag {
    StructTag {
        module: Identifier::new("Event").unwrap(),
        name: Identifier::new("Handle").unwrap(),
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
        module: Identifier::new("Event").unwrap(),
        name: Identifier::new("HandleIdGenerator").unwrap(),
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
        module: Identifier::new("Block").unwrap(),
        name: Identifier::new("T").unwrap(),
        address: core_code_address(),
        type_params: vec![],
    }
}

pub fn get_block_module_def() -> ResourceDef {
    ResourceDef::new(vec![
        ResourceType::U64,
    ])
}