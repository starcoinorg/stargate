use super::*;
use failure::prelude::*;

struct MockStateView{

}

impl StateView for MockStateView{

    fn get(&self, access_path: &AccessPath) -> Result<Option<Vec<u8>>> {
        unimplemented!()
    }

    fn multi_get(&self, access_paths: &[AccessPath]) -> Result<Vec<Option<Vec<u8>>>> {
        unimplemented!()
    }

    fn is_genesis(&self) -> bool {
        unimplemented!()
    }
}

#[test]
fn test_local_vm(){
    let mock_view = Arc::new(AtomicRefCell::new(MockStateView{}));
    let vm = LocalVM::new(mock_view);
}