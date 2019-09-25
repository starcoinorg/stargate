use types::transaction::{Script, TransactionArgument};
use canonical_serialization::{CanonicalDeserialize, CanonicalDeserializer, CanonicalSerialize, CanonicalSerializer, SimpleDeserializer, SimpleSerializer};
use failure::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScriptCode {
    name: String,
    code: Vec<u8>,
}

impl ScriptCode {
    pub fn new(name: String, code: Vec<u8>) -> Self {
        Self {
            name,
            code,
        }
    }

    pub fn code(&self) -> &Vec<u8> {
        &self.code
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn encode_script(self, args: Vec<TransactionArgument>) -> Script {
        Script::new(self.code, args)
    }
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChannelScriptPackage {
    package_name: String,
    scripts: Vec<ScriptCode>,
}

impl ChannelScriptPackage {
    pub fn new(package_name: String, scripts: Vec<ScriptCode>) -> Self {
        Self {
            package_name,
            scripts,
        }
    }

    pub fn package_name(&self) -> &str {
        self.package_name.as_str()
    }

    pub fn get_script(&self, name: &str) -> Option<&ScriptCode> {
        self.scripts.iter().find(|script| script.name.as_str() == name)
    }
}
