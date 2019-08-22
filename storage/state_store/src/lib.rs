use failure::prelude::*;
use logger::prelude::*;
use types::access_path::AccessPath;
use state_view::StateView;
use types::write_set::{WriteSet, WriteOp};
use star_types::change_set::{Changes, ChangeSetMut, StructDefResolve, ChangeSet};
use star_types::resource::Resource;

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

pub trait StateStore : StateViewPlus {

    fn apply_change_set(&self, change_set: &ChangeSet) -> Result<()>{
        for (access_path, changes) in change_set {
            self.apply_changes(access_path, changes)?;
        }
        Ok(())
    }

    fn apply_write_set(&self, write_set: &WriteSet) -> Result<()> {
        self.apply_change_set(&self.write_set_to_change_set(write_set)?)
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
