use failure::prelude::*;
use logger::prelude::*;
use types::access_path::AccessPath;
use state_view::StateView;
use types::write_set::{WriteSet, WriteOp};
use star_types::resource_type::resource_def::{StructDefResolve};
use star_types::resource::Resource;
use std::collections::HashMap;
use types::language_storage::StructTag;
use failure::_core::cell::RefCell;
use types::account_config::coin_struct_tag;

pub trait StateViewPlus: StateView + StructDefResolve {

    fn get_resource(&self, access_path: &AccessPath) -> Result<Option<Resource>>{
        let state = self.get(&access_path)?;
        match state {
            None => Ok(None),
            Some(state) => {
                let tag = access_path.resource_tag().ok_or(format_err!("access_path {:?} is not a resource path.", access_path))?;
                let def = self.resolve(&tag)?;
                Ok(Some(Resource::decode(tag, def, state.as_slice())?))
            }
        }
    }
}

#[derive(Clone,Eq, PartialEq,Debug)]
struct AssetCollector{
    assets:RefCell<HashMap<StructTag, u64>>
}

impl AssetCollector {

    pub fn new() -> Self{
        Self{
            assets: RefCell::new(HashMap::new())
        }
    }

    pub fn incr(&self, tag:&StructTag,incr:u64){
        let mut asserts = self.assets.borrow_mut();
        if asserts.contains_key(tag){
            let old_balance = asserts.get_mut(tag).unwrap();
            let new_balance = *old_balance + incr;
            asserts.insert(tag.clone(),new_balance);
        }else{
            asserts.insert(tag.clone(),incr);
        }
    }

    pub fn visitor(&self, tag:&StructTag, resource:&Resource){
        self.incr(tag, resource.asset_balance().expect("this resource must be asset"))
    }
}

pub trait StateStore : StateViewPlus {

    fn check_asset_balance_by_write_set(&self, write_set: &WriteSet, gas_used:u64) -> Result<()>{
        debug!("check_asset_balance write_set: {} gas_used: {}", write_set.len(), gas_used);
        let mut old_resources = vec![];
        let mut new_resources = vec![];
        for (access_path, op) in write_set {
            match op {
                WriteOp::Deletion => {
                    if !access_path.is_code() {
                        old_resources.push(self.get_resource(access_path)?.ok_or(format_err!("get resource by {:?} fail", access_path))?);
                    }
                },
                WriteOp::Value(value) => {
                    if !access_path.is_code() {
                        let tag = access_path.resource_tag().ok_or(format_err!("get resource tag from path fail."))?;
                        let def = self.resolve(&tag)?;
                        let new_resource = Resource::decode(tag, def, value.as_slice())?;
                        new_resources.push(new_resource);
                        if let Some(old_resource) = self.get_resource(access_path)?{
                            old_resources.push(old_resource);
                        }
                    }
                }
            }
        }
        let old_assets = AssetCollector::new();
        let new_assets = AssetCollector::new();
        for resource in old_resources {
            resource.visit_asset(&|tag,resource|{
                old_assets.visitor(tag, resource)
            })
        }
        for resource in new_resources {
            resource.visit_asset(&|tag,resource|{
                new_assets.visitor(tag, resource)
            })
        }
        new_assets.incr(&coin_struct_tag(), gas_used);
        ensure!(old_assets == new_assets, "old assets {:?} and new assets {:?} is not equals.", old_assets, new_assets);
        Ok(())
    }

    fn apply_write_set(&self, write_set: &WriteSet, gas_used: u64) -> Result<()> {
        if !self.is_genesis() {
            self.check_asset_balance_by_write_set(write_set, gas_used)?;
        }
        for (access_path, op) in write_set {
            match op {
                WriteOp::Deletion => self.delete(access_path)?,
                WriteOp::Value(value) => self.update(access_path, value.clone())?,
            }
        }
        Ok(())
    }

    fn apply_libra_output(&self, txn_output: &types::transaction::TransactionOutput) -> Result<()> {
        self.apply_write_set(txn_output.write_set(), txn_output.gas_used())?;
        Ok(())
    }

    /// Update whole resource value
    fn update(&self, access_path: &AccessPath, value:Vec<u8>) -> Result<()>;

    fn delete(&self, access_path: &AccessPath) -> Result<()>;
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
