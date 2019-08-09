use serde::{Deserialize, Serialize};

use failure::prelude::*;
use proto_conv::{FromProto, IntoProto};
use types::access_path::AccessPath;
use vm_runtime_types::value::Value;
use std::slice::SliceIndex;
use std::ops::Index;

#[derive(Clone,Debug)]
pub enum ChangeOp {
    None,
    Plus(u64),
    Minus(u64),
    Update(Value),
    Deletion,
}

impl ChangeOp {
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

#[derive(Clone, Debug)]
pub struct ChangeSet(ChangeSetMut);

impl ChangeSet {
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[inline]
    pub fn iter<'a>(&'a self) -> ::std::slice::Iter<'a, (AccessPath, ChangeOp)> {
        self.into_iter()
    }

    #[inline]
    pub fn into_mut(self) -> ChangeSetMut {
        self.0
    }

    pub fn merge(first: ChangeSet, second: ChangeSet) -> Result<ChangeSet> {
        ChangeSetMut::merge(first.0, second.0).and_then(|change_set|change_set.freeze())
    }
}

#[derive(Clone, Debug, Default)]
pub struct ChangeSetMut {
    change_set: Vec<(AccessPath, ChangeOp)>,
}

impl ChangeSetMut {
    pub fn new(change_set: Vec<(AccessPath, ChangeOp)>) -> Self {
        Self { change_set }
    }

    pub fn push(&mut self, item: (AccessPath, ChangeOp)) {
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

    pub fn get_change(&self, access_path: &AccessPath) -> Option<&ChangeOp> {
        self.change_set.iter().find(|(ap, change)| ap == access_path).map(|(_, change)| change)
    }

    pub fn merge(first: ChangeSetMut, second: ChangeSetMut) -> Result<ChangeSetMut> {
        let mut change_set = vec![];
        for (ap, first_change) in &first.change_set {
            match second.get_change(&ap) {
                Some(second_change) => {
                    change_set.push((ap.clone(), ChangeOp::merge(first_change, second_change)?));
                }
                None => {
                    change_set.push((ap.clone(), first_change.clone()));
                }
            }
        }
        Ok(ChangeSetMut::new(change_set))
    }
}

impl Index<usize> for ChangeSetMut {
    type Output = (AccessPath,ChangeOp);

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.change_set[index]
    }
}


impl ::std::iter::FromIterator<(AccessPath, ChangeOp)> for ChangeSetMut {
    fn from_iter<I: IntoIterator<Item=(AccessPath, ChangeOp)>>(iter: I) -> Self {
        let mut ws = ChangeSetMut::default();
        for write in iter {
            ws.push((write.0, write.1));
        }
        ws
    }
}

impl<'a> IntoIterator for &'a ChangeSet {
    type Item = &'a (AccessPath, ChangeOp);
    type IntoIter = ::std::slice::Iter<'a, (AccessPath, ChangeOp)>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.change_set.iter()
    }
}

impl ::std::iter::IntoIterator for ChangeSet {
    type Item = (AccessPath, ChangeOp);
    type IntoIter = ::std::vec::IntoIter<(AccessPath, ChangeOp)>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.change_set.into_iter()
    }
}
