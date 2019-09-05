use failure::prelude::*;
use logger::prelude::*;
use types::access_path::AccessPath;
use state_view::StateView;
use types::write_set::{WriteSet, WriteOp};
use star_types::change_set::{Changes, ChangeSetMut, StructDefResolve, ChangeSet};
use star_types::resource::Resource;
use std::collections::HashMap;
use types::language_storage::StructTag;
use failure::_core::cell::RefCell;
use star_types::channel_transaction::{ChannelTransaction, TransactionOutput};
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
        self.incr(tag, resource.assert_balance().expect("this resource must be asset"))
    }
}

pub trait StateStore : StateViewPlus {

    //TODO optimize
    fn check_asset_balance(&self, change_set: &ChangeSet, gas_used:u64) -> Result<()>{
        let mut old_resources = vec![];
        let mut new_resources = vec![];
        for (access_path, changes) in change_set {
            debug!("check_asset_balance path:{:?} change:{:?}", access_path, changes);
            match changes {
                Changes::Deletion => {
                    if !access_path.is_code() {
                        old_resources.push(self.get_resource(access_path)?.ok_or(format_err!("get resource by {:?} fail", access_path))?);
                    }
                },
                Changes::Value(_) => {},
                Changes::Fields(field_changes) => {
                    let old_resource = self.get_resource(access_path)?;
                    match old_resource {
                        Some(old_resource) => {
                            let mut new_resource = old_resource.clone();
                            new_resource.apply_changes(field_changes)?;
                            new_resources.push(new_resource);
                            old_resources.push(old_resource);
                        },
                        None => {
                            let tag = access_path.resource_tag().ok_or(format_err!("get resource tag from path fail."))?;
                            let def = self.resolve(&tag)?;
                            let new_resource = Resource::from_changes(field_changes, tag,&def);
                            new_resources.push(new_resource);
                        }
                    }
                }
            }
        }
        debug!("old resources {:?}", old_resources);
        debug!("new resources {:?}", new_resources);
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
        debug!("old assets {:?}", old_assets);
        debug!("new assets {:?}", new_assets);
        ensure!(old_assets == new_assets, "old assets {:?} and new assets {:?} is not equals.");
        Ok(())
    }

    fn check_asset_balance_by_write_set(&self, write_set: &WriteSet, gas_used:u64) -> Result<()>{
        let mut old_resources = vec![];
        let mut new_resources = vec![];
        for (access_path, op) in write_set {
            debug!("check_asset_balance path:{:?} op:{:?}", access_path, op);
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
        debug!("old resources {:?}", old_resources);
        debug!("new resources {:?}", new_resources);
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
        debug!("old assets {:?}", old_assets);
        debug!("new assets {:?}", new_assets);
        ensure!(old_assets == new_assets, "old assets {:?} and new assets {:?} is not equals.");
        Ok(())
    }

    fn apply_change_set(&self, change_set: &ChangeSet, gas_used: u64) -> Result<()>{
        if !self.is_genesis() {
            self.check_asset_balance(change_set, gas_used)?;
        }
        for (access_path, changes) in change_set {
            self.apply_changes(access_path, changes)?;
        }
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

    fn apply_changes(&self, access_path: &AccessPath, changes: &Changes) -> Result<()>{
        match changes{
            Changes::Deletion => self.delete(access_path),
            Changes::Value(value) => self.update(access_path, value.clone()),
            Changes::Fields(field_changes) => {
                let old_resource = self.get_resource(access_path)?;
                match old_resource {
                    Some(mut old_resource) => {
                        debug!("apply changes: {:#?} to resource {:#?}", field_changes, old_resource);
                        old_resource.apply_changes(field_changes)?;
                        debug!("merged resource {:#?}", old_resource);
                        self.update(access_path, old_resource.encode())
                    },
                    None => {
                        let tag = access_path.resource_tag().ok_or(format_err!("get resource tag from path fail."))?;
                        let def = self.resolve(&tag)?;
                        debug!("init new resource {:?} from change {:#?}", tag, field_changes);
                        let new_resource = Resource::from_changes(field_changes, tag,&def);
                        debug!("result {:?}", new_resource);
                        self.update(access_path, new_resource.encode())
                    }
                }
            }
        }
    }

    fn write_set_to_change_set(&self, write_set: &WriteSet) -> Result<ChangeSet> {
        let change_set:Result<Vec<(AccessPath, Changes)>> = write_set.iter().map(|(ap,write_op)|{
            debug!("write_set_to_change_set account:{} data_path:{:?}", ap.address, ap.data_path());
            let changes = match write_op {
                WriteOp::Deletion => Changes::Deletion,
                WriteOp::Value(value) => if ap.is_code(){
                    Changes::Value(value.clone())
                }else{
                    let old_resource = self.get_resource(ap)?;
                    let tag = ap.resource_tag().ok_or(format_err!("get resource tag fail"))?;
                    let def = self.resolve(&tag)?;
                    let new_resource = Resource::decode(tag,def, value.as_slice())?;

                    let field_changes = match old_resource {
                        Some(old_resource) => old_resource.diff(&new_resource)?,
                        None => new_resource.to_changes()
                    };
                    Changes::Fields(field_changes)
                }
            };
            Ok((ap.clone(), changes))
        }).collect();
        ChangeSetMut::new(change_set?).freeze()
    }

    fn apply_txn(&self, txn: &ChannelTransaction) -> Result<()> {
        self.apply_output(txn.output())
    }

    fn apply_output(&self, txn_output: &TransactionOutput) -> Result<()> {
        self.apply_change_set(txn_output.change_set(), txn_output.gas_used())?;
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
