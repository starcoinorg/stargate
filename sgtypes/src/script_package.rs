// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Error, Result};
use libra_crypto::hash::{CryptoHash, CryptoHasher, TestOnlyHasher};
use libra_crypto::HashValue;
use libra_types::transaction::{Script, TransactionArgument};
use serde::{Deserialize, Serialize};
use serde_json;
use std::{
    convert::TryFrom,
    fmt::{Display, Formatter},
    fs,
    io::Write,
    path::Path,
};

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScriptCode {
    name: String,
    source_code: String,
    byte_code: Vec<u8>,
}

impl ScriptCode {
    pub fn new(name: String, source_code: String, byte_code: Vec<u8>) -> Self {
        Self {
            name,
            source_code,
            byte_code,
        }
    }

    pub fn byte_code(&self) -> &Vec<u8> {
        &self.byte_code
    }

    pub fn source_code(&self) -> &str {
        self.source_code.as_str()
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn encode_script(self, args: Vec<TransactionArgument>) -> Script {
        Script::new(self.byte_code, args)
    }
}

impl TryFrom<crate::proto::sgtypes::ScriptCode> for ScriptCode {
    type Error = Error;

    fn try_from(proto: crate::proto::sgtypes::ScriptCode) -> Result<Self> {
        Ok(Self {
            name: proto.name,
            source_code: proto.source_code,
            byte_code: proto.byte_code.as_slice().to_vec(),
        })
    }
}

impl From<ScriptCode> for crate::proto::sgtypes::ScriptCode {
    fn from(script_code: ScriptCode) -> Self {
        Self {
            name: script_code.name,
            source_code: script_code.source_code,
            byte_code: script_code.byte_code.to_vec(),
        }
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
        self.scripts
            .iter()
            .find(|script| script.name.as_str() == name)
    }

    pub fn dump_to(&self, path: &Path) {
        let csp_bytes = serde_json::to_vec(&self).expect("Unable to serialize program");
        let mut f = fs::File::create(path)
            .unwrap_or_else(|err| panic!("Unable to open output file {:?}: {}", path, err));
        f.write_all(&csp_bytes)
            .unwrap_or_else(|err| panic!("Unable to write to output file {:?}: {}", path, err));
    }
}

impl CryptoHash for ChannelScriptPackage {
    type Hasher = TestOnlyHasher;

    fn hash(&self) -> HashValue {
        let mut state = Self::Hasher::default();
        state.write(
            lcs::to_bytes(self)
                .expect("Failed to serialize ChannelTransaction")
                .as_slice(),
        );
        state.finish()
    }
}

impl Display for ChannelScriptPackage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "package: {}", self.package_name())?;
        for script in &self.scripts {
            writeln!(f, "script: {}", script.name())?;
            writeln!(f, "---------------------------")?;
            writeln!(f, "source:")?;
            writeln!(f, "{}", script.source_code())?;
            writeln!(f, "---------------------------")?;
        }
        Ok(())
    }
}

impl TryFrom<crate::proto::sgtypes::ChannelScriptPackage> for ChannelScriptPackage {
    type Error = Error;
    fn try_from(proto_package: crate::proto::sgtypes::ChannelScriptPackage) -> Result<Self> {
        Ok(Self {
            package_name: proto_package.package_name,
            scripts: proto_package
                .scripts
                .into_iter()
                .map(ScriptCode::try_from)
                .collect::<Result<Vec<_>>>()?,
        })
    }
}

impl From<ChannelScriptPackage> for crate::proto::sgtypes::ChannelScriptPackage {
    fn from(package: ChannelScriptPackage) -> Self {
        Self {
            package_name: package.package_name,
            scripts: package.scripts.into_iter().map(Into::into).collect(),
        }
    }
}
