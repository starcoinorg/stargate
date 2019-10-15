use std::collections::HashMap;

use failure::_core::cell::RefCell;
use ir_to_bytecode::{compiler::compile_module, parser::parse_module};

use super::*;

static EMPTY_MODULE_TPL: &'static str = "module $name {public do_nothing(){
        return;
    }}";

pub struct MockModuleLoader {
    modules: RefCell<HashMap<ModuleId, Vec<u8>>>,
}

impl MockModuleLoader {
    pub fn new() -> Self {
        Self {
            modules: RefCell::new(HashMap::new()),
        }
    }

    pub fn register_module(&self, module_id: ModuleId, byte_code: Vec<u8>) {
        self.modules.borrow_mut().insert(module_id, byte_code);
    }

    pub fn mock_empty_module(&self, module_id: &ModuleId) -> Result<()> {
        let src = EMPTY_MODULE_TPL.replace("$name", module_id.name().as_str());
        let module = parse_module(src.as_str())?;
        let (compiled_module, _) = compile_module(*module_id.address(), module, stdlib_modules())?;
        let mut byte_code = vec![];
        compiled_module.serialize(&mut byte_code)?;
        self.register_module(module_id.clone(), byte_code);
        Ok(())
    }
}

impl ModuleLoader for MockModuleLoader {
    fn load_module(&self, module_id: &ModuleId) -> Result<Option<Vec<u8>>> {
        Ok(self.modules.borrow().get(module_id).cloned())
    }
}
