use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use crypto::HashValue;
use star_types::message::StructTag;
use vm_runtime_types::loaded_data::struct_def::StructDef;

pub struct StructStorage {
    struct_map: HashMap<HashValue, (StructTag, StructDef)>
}

impl StructStorage {
    pub fn new() -> Self {
        let struct_map = HashMap::new();
        StructStorage { struct_map }
    }
}