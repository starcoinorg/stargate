use std::ops::Index;
use std::slice::SliceIndex;

use serde::{Deserialize, Serialize};

use failure::prelude::*;
use proto_conv::{FromProto, IntoProto};
use types::access_path::{AccessPath, Accesses};
use std::mem;
use crate::{
    resource_type::{resource_def::ResourceDef, resource_types::ResourceType},
    resource_value::{ResourceValue,MutResourceVal},
    proto::change_set::ChangeOp_oneof_change,
};
use canonical_serialization::{SimpleDeserializer, SimpleSerializer};
use radix_trie::TrieKey;
use types::write_set::WriteSet;
use types::language_storage::StructTag;
use types::byte_array::ByteArray;
use types::account_address::AccountAddress;
use std::convert::TryFrom;
use crate::resource::Resource;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChangeOp {
    None,
    Plus(u64),
    Minus(u64),
    Update(Vec<u8>),
    Deletion,
}

impl ChangeOp {
    pub fn is_none(&self) -> bool {
        match self {
            ChangeOp::None => true,
            _ => false
        }
    }

    pub fn is_deletion(&self) -> bool {
        match self {
            ChangeOp::Deletion => true,
            _ => false
        }
    }

    pub fn as_plus(&self) -> Option<u64> {
        match self {
            ChangeOp::Plus(value) => Some(*value),
            _ => None
        }
    }

    pub fn as_minus(&self) -> Option<u64> {
        match self {
            ChangeOp::Minus(value) => Some(*value),
            _ => None
        }
    }

    /// return old value.
    pub fn merge_with(&mut self, other: &ChangeOp) -> Result<ChangeOp> {
        let mut change_op = Self::merge(self, other)?;
        Ok(mem::replace(self, change_op))
    }

    pub fn merge(first: &ChangeOp, second: &ChangeOp) -> Result<ChangeOp> {
        match first {
            ChangeOp::None => Ok(second.clone()),
            ChangeOp::Plus(first_value) => {
                match second {
                    ChangeOp::None => Ok(ChangeOp::Plus(*first_value)),
                    ChangeOp::Plus(second_value) => Ok(ChangeOp::Plus(first_value + second_value)),
                    ChangeOp::Minus(second_value) => {
                        if first_value == second_value {
                            Ok(ChangeOp::None)
                        } else if first_value > second_value {
                            Ok(ChangeOp::Plus(first_value - second_value))
                        } else {
                            Ok(ChangeOp::Minus(second_value - first_value))
                        }
                    }
                    _ => bail!("can not merge  ChangeOp:{:?},{:?}", first, second),
                }
            }
            ChangeOp::Minus(first_value) => {
                match second {
                    ChangeOp::None => Ok(ChangeOp::Minus(*first_value)),
                    ChangeOp::Plus(second_value) => {
                        if first_value == second_value {
                            Ok(ChangeOp::None)
                        } else if first_value > second_value {
                            Ok(ChangeOp::Minus(first_value - second_value))
                        } else {
                            Ok(ChangeOp::Plus(second_value - first_value))
                        }
                    }
                    ChangeOp::Minus(second_value) => Ok(ChangeOp::Minus(first_value + second_value)),
                    _ => bail!("can not merge  ChangeOp:{:?},{:?}", first, second),
                }
            }
            ChangeOp::Update(first_value) => {
                match second {
                    ChangeOp::None => Ok(ChangeOp::Update(first_value.clone())),
                    ChangeOp::Update(second_value) => Ok(ChangeOp::Update(second_value.clone())),
                    ChangeOp::Deletion => Ok(ChangeOp::Deletion),
                    _ => bail!("can not merge  ChangeOp:{:?},{:?}", first, second),
                }
            }
            ChangeOp::Deletion => {
                match second {
                    ChangeOp::None => Ok(ChangeOp::Deletion),
                    ChangeOp::Deletion => Ok(ChangeOp::Deletion),
                    ChangeOp::Update(second_value) => Ok(ChangeOp::Update(second_value.clone())),
                    _ => bail!("can not merge  ChangeOp:{:?},{:?}", first, second),
                }
            }
        }
    }
}

pub trait Changeable{

    fn apply_change(&mut self, op: ChangeOp) -> Result<()>;

}

impl Changeable for MutResourceVal {

    fn apply_change(&mut self, op: ChangeOp) -> Result<()> {
        let value = match &*self.peek(){
            ResourceValue::U64(value) => match op{
                //TODO check overflow
                ChangeOp::Plus(op_value) => ResourceValue::U64(*value+ op_value),
                ChangeOp::Minus(op_value) => {
                    println!("{} - {} ",value,op_value);
                    ResourceValue::U64(*value - op_value)
                },
                _ => bail!("Can not apply change {:?} to {:?}", op, self)
            },
            ResourceValue::ByteArray(_) => match op {
                ChangeOp::Update(bytes) => ResourceValue::ByteArray(ByteArray::new(bytes)),
                _ => bail!("Can not apply change {:?} to {:?}", op, self)
            },
            ResourceValue::String(_) => match op {
                ChangeOp::Update(bytes) => ResourceValue::String(String::from_utf8(bytes)?),
                _ => bail!("Can not apply change {:?} to {:?}", op, self)
            },
            ResourceValue::Bool(_) => match op {
                ChangeOp::Update(bytes) => ResourceValue::Bool(bytes[0]!=0),
                _ => bail!("Can not apply change {:?} to {:?}", op, self)
            },
            ResourceValue::Address(_) => match op {
                ChangeOp::Update(bytes) => ResourceValue::Address(AccountAddress::try_from(bytes)?),
                _ => bail!("Can not apply change {:?} to {:?}", op, self)
            }
            _ => bail!("Can not apply change {:?} to {:?}", op, self)
        };
        //println!("replace {:?}", value);
        self.0.replace(value);
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangeSet(ChangeSetMut);

impl ChangeSet {

    pub fn empty() -> Self{
        ChangeSetMut::empty().freeze().unwrap()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[inline]
    pub fn iter(&self) -> ::std::slice::Iter<(AccessPath, Changes)> {
        self.into_iter()
    }

    #[inline]
    pub fn into_mut(self) -> ChangeSetMut {
        self.0
    }

    pub fn merge(first: &ChangeSet, second: &ChangeSet) -> Result<ChangeSet> {
        ChangeSetMut::merge(&first.0, &second.0).and_then(|change_set| change_set.freeze())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Changes {
    Value(Vec<u8>),
    Fields(FieldChanges),
    Deletion,
}

impl Changes {

    /// merge other with self, and return old self
    pub fn merge_with(&mut self, other: &Changes) -> Result<Changes>{
        match (self, other){
            (Changes::Value {..}, Changes::Value{..}) => bail!("Unsupported whole value merge."),
            (Changes::Deletion, Changes::Deletion) => bail!("Unsupported deletion merge."),
            (Changes::Fields(field_changes), Changes::Fields(other_field_changes)) => {
                Ok(Changes::Fields(field_changes.merge_with(other_field_changes)?))
            },
            (first,second) => {
                bail!("Unsupported merge {:?} with {:?}", first, second)
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldChanges(Vec<(Accesses, ChangeOp)>);

impl FieldChanges {
    pub fn empty() -> Self {
        Self(vec![])
    }

    pub fn new(changes: Vec<(Accesses, ChangeOp)>) -> Self {
        Self(changes)
    }

    /// Create whole resource deletion changes
    pub fn delete(resource: Resource) -> Self{
        let fields = resource.fields();
        Self::new(Self::delete_fields(&fields))
    }

    fn delete_fields(fields: &Vec<MutResourceVal>) -> Vec<(Accesses, ChangeOp)> {
        let mut results = vec![];
        for (idx, field) in fields.iter().enumerate(){
            let mut changes = Self::delete_field(idx, field);
            results.append(&mut changes);
        }
        results
    }

    fn delete_field(idx:usize, field: &MutResourceVal) -> Vec<(Accesses,ChangeOp)> {
        let mut accesses = Accesses::new_with_index(idx as u64);
        let mut results = vec![];
        match &*field.peek() {
            ResourceValue::U64(value) => {
                let op = ChangeOp::Minus(*value);
                results.push((accesses, op));
            },
            ResourceValue::Resource(res) => {
                let changes = Self::delete_fields(res.fields());
                for (mut sub_accesses, change_op) in changes {
                    let mut accesses = accesses.clone();
                    accesses.append(&mut sub_accesses);
                    results.push((accesses, change_op));
                }
            }
            _ => {
                results.push((accesses, ChangeOp::Deletion));
            }
        }
        results
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[inline]
    pub fn iter(&self) -> ::std::slice::Iter<(Accesses, ChangeOp)> {
        self.into_iter()
    }

    pub fn append(&mut self, other: &mut FieldChanges) {
        self.0.append(&mut other.0)
    }

    pub fn push(&mut self, item: (Accesses, ChangeOp)) {
        self.0.push(item)
    }

    pub fn get_change(&self, accesses: &Accesses) -> Option<&ChangeOp> {
        self.iter().find(|(ac, _)| ac == accesses).map(|(_, change)| change)
    }

    pub fn get_change_mut(&mut self, accesses: &Accesses) -> Option<&mut ChangeOp> {
        self.0.iter_mut().find(|(ac, _)| ac == accesses).map(|(_, change)| change)
    }

    pub fn merge_with(&mut self, other: &FieldChanges) -> Result<FieldChanges> {
        let mut changes = Self::merge(self, other)?;
        Ok(mem::replace(self, changes))
    }

    pub fn merge(first: &FieldChanges, second: &FieldChanges) -> Result<FieldChanges> {
        let mut changes = first.clone();
        for (accesses, second_change_op) in second {
            match changes.get_change_mut(&accesses) {
                Some(change_op) => {
                    change_op.merge_with(second_change_op)?;
                }
                None => {
                    changes.push((accesses.clone(), second_change_op.clone()))
                }
            }
        }
        Ok(changes)
    }

    pub fn filter_none(&mut self) {
        let mut changes = FieldChanges::new(self.0.iter().filter(|(_, change_op)| !change_op.is_none()).cloned().collect());
        mem::replace(self, changes);
    }
}


impl ::std::iter::IntoIterator for FieldChanges {
    type Item = (Accesses, ChangeOp);
    type IntoIter = ::std::vec::IntoIter<(Accesses, ChangeOp)>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}


impl<'a> IntoIterator for &'a FieldChanges {
    type Item = &'a (Accesses, ChangeOp);
    type IntoIter = ::std::slice::Iter<'a, (Accesses, ChangeOp)>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}


impl Index<usize> for FieldChanges {
    type Output = (Accesses, ChangeOp);

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl FromProto for FieldChanges {
    type ProtoType = crate::proto::change_set::FieldChanges;

    fn from_proto(mut object: Self::ProtoType) -> Result<Self> {
        use ::protobuf::RepeatedField;
        use crate::proto::change_set::{ChangeOpType_oneof_change_type, ChangeSet as ChangeSetProto};

        Ok(FieldChanges::new(object.take_field_changes().iter_mut().map(|field_change|{
            let accesses = Accesses::from_separated_string(String::from_utf8(field_change.take_accesses()).unwrap().as_str()).unwrap();
            let change_type = field_change.take_change_type().change_type;
            let change_op = match change_type {
                None => ChangeOp::None,
                Some(change_type) => match change_type {
                    ChangeOpType_oneof_change_type::None(_) => { ChangeOp::None }
                    ChangeOpType_oneof_change_type::Plus(data) => {
                        ChangeOp::Plus(data)
                    }
                    ChangeOpType_oneof_change_type::Minus(data) => {
                        ChangeOp::Minus(data)
                    }
                    ChangeOpType_oneof_change_type::Update(blob) => {
                        ChangeOp::Update(blob)
                    }
                    ChangeOpType_oneof_change_type::Deletion(_) => {
                        ChangeOp::Deletion
                    }
                }
            };
            (accesses, change_op)
        }).collect()))
    }
}

impl IntoProto for FieldChanges {
    type ProtoType = crate::proto::change_set::FieldChanges;

    fn into_proto(self) -> Self::ProtoType {
        use ::protobuf::RepeatedField;
        use crate::proto::change_set::{ChangeOp as ProtoChangeOp, ChangeOpType, FieldChange};

        let mut field_changes = Self::ProtoType::new();
        let mut fields = RepeatedField::new();
        self.iter().for_each(|(accesses, change_op)| {
            let accesses_bytes = accesses.to_bytes();
            let mut change_op_type = ChangeOpType::new();
            match change_op {
                ChangeOp::None => {
                    change_op_type.set_None(true);
                }
                ChangeOp::Plus(data) => {
                    change_op_type.set_Plus(*data);
                }
                ChangeOp::Minus(data) => {
                    change_op_type.set_Minus(*data)
                }
                ChangeOp::Update(val) => {
                    change_op_type.set_Update(val.clone());
                }
                ChangeOp::Deletion => {
                    change_op_type.set_Deletion(true)
                }
            };
            let mut field_change = FieldChange::new();
            field_change.set_accesses(accesses_bytes);
            field_change.set_change_type(change_op_type);
            fields.push(field_change)
        });
        field_changes.set_field_changes(fields);
        field_changes
    }
}

pub trait StructDefResolve{

    fn resolve(&self, tag: &StructTag) -> Result<ResourceDef>;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ChangeSetMut {
    change_set: Vec<(AccessPath, Changes)>,
}

impl ChangeSetMut {
    pub fn new(change_set: Vec<(AccessPath, Changes)>) -> Self {
        Self { change_set }
    }

    pub fn empty() -> Self {
        Self::new(vec![])
    }

    pub fn push(&mut self, item: (AccessPath, Changes)) {
        self.change_set.push(item);
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.change_set.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.change_set.is_empty()
    }

    pub fn freeze(self) -> Result<ChangeSet> {
        // TODO: add structural validation
        Ok(ChangeSet(self))
    }

    pub fn get_changes(&self, access_path: &AccessPath) -> Option<&Changes> {
        self.change_set.iter().find(|(ap, _)| ap == access_path).map(|(_, change)| change)
    }

    pub fn get_changes_mut(&mut self, access_path: &AccessPath) -> Option<&mut Changes> {
        self.change_set.iter_mut().find(|(ap, _)| ap == access_path).map(|(_, change)| change)
    }

    /// return old change set
    pub fn merge_with(&mut self, other: &ChangeSetMut) -> Result<ChangeSetMut> {
        let mut change_set = Self::merge(self, other)?;
        Ok(mem::replace(self, change_set))
    }

    pub fn merge(first: &ChangeSetMut, second: &ChangeSetMut) -> Result<ChangeSetMut> {
        let mut change_set = first.clone();
        for (ap, second_change) in &second.change_set {
            match change_set.get_changes_mut(ap) {
                Some(first_change) => {
                    first_change.merge_with(second_change)?;
                }
                None => {
                    change_set.push((ap.clone(), second_change.clone()));
                }
            }
        }
        Ok(change_set)
    }
}

impl Index<usize> for ChangeSetMut {
    type Output = (AccessPath, Changes);

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.change_set[index]
    }
}


impl ::std::iter::FromIterator<(AccessPath, Changes)> for ChangeSetMut {
    fn from_iter<I: IntoIterator<Item=(AccessPath, Changes)>>(iter: I) -> Self {
        let mut cs = ChangeSetMut::default();
        for change in iter {
            cs.push((change.0, change.1));
        }
        cs
    }
}

impl<'a> IntoIterator for &'a ChangeSet {
    type Item = &'a (AccessPath, Changes);
    type IntoIter = ::std::slice::Iter<'a, (AccessPath, Changes)>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.change_set.iter()
    }
}

impl ::std::iter::IntoIterator for ChangeSet {
    type Item = (AccessPath, Changes);
    type IntoIter = ::std::vec::IntoIter<(AccessPath, Changes)>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.change_set.into_iter()
    }
}

impl FromProto for ChangeSet {
    type ProtoType = crate::proto::change_set::ChangeSet;

    fn from_proto(mut change_set_pb: Self::ProtoType) -> Result<Self> {
        use ::protobuf::RepeatedField;
        use crate::proto::change_set::ChangeOpType;
        let change_set:Result<Vec<(AccessPath, Changes)>> = change_set_pb.take_changes().iter_mut().map(|change_op_pb| {
            let access_path = AccessPath::from_proto(change_op_pb.take_access_path())?;
            let changes = match change_op_pb.change.clone().ok_or(format_err!("change is none"))?{
                    ChangeOp_oneof_change::Value(value) => {
                        Changes::Value(value)
                    },
                    ChangeOp_oneof_change::Fields(field_changes) => {
                        Changes::Fields(FieldChanges::from_proto(field_changes)?)
                    },
                    ChangeOp_oneof_change::Deletion(_) => {
                        Changes::Deletion
                    }
            };
            Ok((access_path, changes))
        }).collect();

        let write_set_mut = ChangeSetMut::new(change_set?);
        write_set_mut.freeze()
    }
}

impl IntoProto for ChangeSet {
    type ProtoType = crate::proto::change_set::ChangeSet;

    fn into_proto(self) -> Self::ProtoType {
        use ::protobuf::RepeatedField;
        use crate::proto::change_set::{ChangeOp as ProtoChangeOp, ChangeOpType, FieldChange, ChangeSet as ChangeSetProto};

        let mut change_set = RepeatedField::new();
        self.iter().for_each(|(access_path, changes)| {
            let access_path_pb = access_path.clone().into_proto();
            let mut change_op_pb = ProtoChangeOp::new();
            match changes{
                Changes::Value(code) => change_op_pb.set_Value(code.clone()),
                Changes::Fields(field_changes) => change_op_pb.set_Fields(field_changes.clone().into_proto()),
                Changes::Deletion => change_op_pb.set_Deletion(true),
            };
            change_op_pb.set_access_path(access_path_pb);
            change_set.push(change_op_pb);
        });

        let mut change_set_pb = ChangeSetProto::new();
        change_set_pb.set_changes(change_set);
        change_set_pb
    }
}