// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use std::{
    cell::{Ref, RefCell},
    ops::Add,
    rc::Rc,
};
use types::{
    access_path::AccessPath,
    account_address::{AccountAddress, ADDRESS_LENGTH},
    byte_array::ByteArray,
    contract_event::ContractEvent,
};
use failure::prelude::*;
use crate::resource_type::{resource_types::ResourceType, resource_def::ResourceDef};
use types::language_storage::StructTag;
use crate::resource::Resource;

#[derive(Debug, Clone)]
pub enum ResourceValue {
    Address(AccountAddress),
    U64(u64),
    Bool(bool),
    String(String),
    Resource(Resource),
    ByteArray(ByteArray),
}

impl ResourceValue {

    /// Normal code should always know what type this value has. This is made available only for
    /// tests.
    #[allow(non_snake_case)]
    #[doc(hidden)]
    pub fn to_resource_def_FOR_TESTING(&self) -> ResourceDef {
        let res = match self {
            ResourceValue::Resource(res) => res,
            _ => panic!("Value must be a struct {:?}", self),
        };
        res.to_resource_def_FOR_TESTING()
    }

    // Structural equality for Move values
    // Cannot use Rust's equality due to:
    // - Collections possibly having different representations but still being "equal" semantically
    pub fn equals(&self, v2: &ResourceValue) -> Result<bool> {
        Ok(match (self, v2) {
            (ResourceValue::Bool(b1), ResourceValue::Bool(b2)) => b1 == b2,
            (ResourceValue::Address(a1), ResourceValue::Address(a2)) => a1 == a2,
            (ResourceValue::U64(u1), ResourceValue::U64(u2)) => u1 == u2,
            (ResourceValue::String(s1), ResourceValue::String(s2)) => s1 == s2,
            (ResourceValue::Resource(s1), ResourceValue::Resource(s2)) => {
                if s1.tag() != s2.tag() {
                    //TODO custom error
                    bail!("InternalTypeError");
                }
                if s1.len() != s2.len() {
                    bail!("InternalTypeError");
                }
                for (mv1, mv2) in s1.iter().zip(s2.iter()) {
                    if !MutResourceVal::equals(mv1, mv2)? {
                        return Ok(false);
                    }
                }
                true
            }
            (ResourceValue::ByteArray(ba1), ResourceValue::ByteArray(ba2)) => ba1 == ba2,
            _ => bail!("InternalTypeError"),
        })
    }

    // Structural non-equality for Move values
    // Implemented by hand instead of `!equals` to allow for short circuiting
    pub fn not_equals(&self, v2: &ResourceValue) -> Result<bool> {
        Ok(match (self, v2) {
            (ResourceValue::Bool(b1), ResourceValue::Bool(b2)) => b1 != b2,
            (ResourceValue::Address(a1), ResourceValue::Address(a2)) => a1 != a2,
            (ResourceValue::U64(u1), ResourceValue::U64(u2)) => u1 != u2,
            (ResourceValue::String(s1), ResourceValue::String(s2)) => s1 != s2,
            (ResourceValue::Resource(s1), ResourceValue::Resource(s2)) => {
                if s1.tag() != s2.tag() {
                    bail!("InternalTypeError");
                }
                if s1.len() != s2.len() {
                    bail!("InternalTypeError");
                }
                for (mv1, mv2) in s1.iter().zip(s2.iter()) {
                    if MutResourceVal::not_equals(mv1, mv2)? {
                        return Ok(true);
                    }
                }
                false
            }
            (ResourceValue::ByteArray(ba1), ResourceValue::ByteArray(ba2)) => ba1 != ba2,
            _ => bail!("InternalTypeError"),
        })
    }

    pub fn is_u64(&self) -> bool {
        match self{
            ResourceValue::U64(_) => true,
            _ => false
        }
    }

    pub fn is_bool(&self) -> bool {
        match self{
            ResourceValue::Bool(_) => true,
            _ => false
        }
    }

    pub fn is_address(&self) -> bool {
        match self{
            ResourceValue::Address(_) => true,
            _ => false
        }
    }

    pub fn is_byte_array(&self) -> bool {
        match self{
            ResourceValue::ByteArray(_) => true,
            _ => false
        }
    }

    pub fn is_string(&self) -> bool {
        match self{
            ResourceValue::String(_) => true,
            _ => false
        }
    }

    pub fn is_resource(&self) -> bool {
        match self{
            ResourceValue::Resource(_) => true,
            _ => false
        }
    }

}


#[derive(Debug)]
pub struct MutResourceVal(pub Rc<RefCell<ResourceValue>>);

impl Clone for MutResourceVal {
    fn clone(&self) -> Self {
        MutResourceVal(Rc::new(RefCell::new(self.peek().clone())))
    }
}

impl MutResourceVal {
    pub fn try_own(mv: Self) -> Result<ResourceValue> {
        match Rc::try_unwrap(mv.0) {
            Ok(cell) => Ok(cell.into_inner()),
            Err(_) => bail!("VMInvariantViolation::LocalReferenceError"),
        }
    }

    pub fn peek(&self) -> Ref<ResourceValue> {
        self.0.borrow()
    }

    pub fn new(v: ResourceValue) -> Self {
        MutResourceVal(Rc::new(RefCell::new(v)))
    }

    //TODO ensure is pub
    pub fn shallow_clone(&self) -> Self {
        MutResourceVal(Rc::clone(&self.0))
    }

    fn address(addr: AccountAddress) -> Self {
        MutResourceVal::new(ResourceValue::Address(addr))
    }

    fn u64(i: u64) -> Self {
        MutResourceVal::new(ResourceValue::U64(i))
    }

    fn bool(b: bool) -> Self {
        MutResourceVal::new(ResourceValue::Bool(b))
    }

    fn string(s: String) -> Self {
        MutResourceVal::new(ResourceValue::String(s))
    }

    fn resource(tag: StructTag, v: Vec<MutResourceVal>) -> Self {
        MutResourceVal::new(ResourceValue::Resource(Resource::new(tag, v)))
    }

    fn bytearray(v: ByteArray) -> Self {
        MutResourceVal::new(ResourceValue::ByteArray(v))
    }

    // Structural equality for Move values
    // Cannot use Rust's equality due to:
    // - Collections possibly having different representations but still being "equal" semantically
    pub fn equals(&self, mv2: &MutResourceVal) -> Result<bool> {
        self.peek().equals(&mv2.peek())
    }

    // Structural non-equality for Move values
    // Implemented by hand instead of `!equals` to allow for short circuiting
    pub fn not_equals(&self, mv2: &MutResourceVal) -> Result<bool> {
        self.peek().not_equals(&mv2.peek())
    }

    pub fn is_u64(&self) -> bool {
        match &*self.peek(){
            ResourceValue::U64(_) => true,
            _ => false
        }
    }

    pub fn is_bool(&self) -> bool {
        match &*self.peek(){
            ResourceValue::Bool(_) => true,
            _ => false
        }
    }

    pub fn is_address(&self) -> bool {
        match &*self.peek(){
            ResourceValue::Address(_) => true,
            _ => false
        }
    }

    pub fn is_byte_array(&self) -> bool {
        match &*self.peek(){
            ResourceValue::ByteArray(_) => true,
            _ => false
        }
    }

    pub fn is_string(&self) -> bool {
        match &*self.peek(){
            ResourceValue::String(_) => true,
            _ => false
        }
    }

    pub fn is_resource(&self) -> bool {
        match &*self.peek(){
            ResourceValue::Resource(_) => true,
            _ => false
        }
    }

    pub fn borrow_field(&self, idx: u32) -> Option<Self> {
        match &*self.peek() {
            ResourceValue::Resource(res) => res.field(idx as usize).map(MutResourceVal::shallow_clone),
            _ => None,
        }
    }

    pub fn read_reference(self) -> MutResourceVal {
        self.clone()
    }

    pub fn mutate_reference(self, v: MutResourceVal) {
        self.0.replace(v.peek().clone());
    }
}

//
// Conversion routines for the interpreter
//

impl From<MutResourceVal> for Option<u64> {
    fn from(value: MutResourceVal) -> Option<u64> {
        match &*value.peek() {
            ResourceValue::U64(i) => Some(*i),
            _ => None,
        }
    }
}

impl From<MutResourceVal> for Option<bool> {
    fn from(value: MutResourceVal) -> Option<bool> {
        match &*value.peek() {
            ResourceValue::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

impl From<MutResourceVal> for Option<AccountAddress> {
    fn from(value: MutResourceVal) -> Option<AccountAddress> {
        match *value.peek() {
            ResourceValue::Address(addr) => Some(addr),
            _ => None,
        }
    }
}

impl From<MutResourceVal> for Option<ByteArray> {
    fn from(value: MutResourceVal) -> Option<ByteArray> {
        match &*value.peek() {
            ResourceValue::ByteArray(blob) => Some(blob.clone()),
            _ => None,
        }
    }
}