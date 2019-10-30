// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use canonical_serialization::{
    CanonicalDeserialize, CanonicalDeserializer, CanonicalSerialize, CanonicalSerializer,
    SimpleDeserializer, SimpleSerializer,
};
use crypto::hash::{CryptoHash, CryptoHasher, TestOnlyHasher};
use crypto::HashValue;
use failure::prelude::*;
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

impl CanonicalSerialize for ScriptCode {
    fn serialize(&self, serializer: &mut impl CanonicalSerializer) -> Result<()> {
        serializer
            .encode_string(self.name.as_str())?
            .encode_string(self.source_code.as_str())?
            .encode_bytes(self.byte_code.as_slice())?;
        Ok(())
    }
}

impl CanonicalDeserialize for ScriptCode {
    fn deserialize(deserializer: &mut impl CanonicalDeserializer) -> Result<Self>
    where
        Self: Sized,
    {
        let name = deserializer.decode_string()?;
        let source_code = deserializer.decode_string()?;
        let byte_code = deserializer.decode_bytes()?;
        Ok(Self {
            name,
            source_code,
            byte_code,
        })
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
            SimpleSerializer::<Vec<u8>>::serialize(self)
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

impl CanonicalSerialize for ChannelScriptPackage {
    fn serialize(&self, serializer: &mut impl CanonicalSerializer) -> Result<()> {
        serializer
            .encode_string(self.package_name.as_str())?
            .encode_vec(&self.scripts)?;
        Ok(())
    }
}

impl CanonicalDeserialize for ChannelScriptPackage {
    fn deserialize(deserializer: &mut impl CanonicalDeserializer) -> Result<Self>
    where
        Self: Sized,
    {
        let package_name = deserializer.decode_string()?;
        let scripts = deserializer.decode_vec()?;
        Ok(Self {
            package_name,
            scripts,
        })
    }
}

impl TryFrom<crate::proto::sgtypes::ChannelScriptPackage> for ChannelScriptPackage {
    type Error = Error;
    fn try_from(value: crate::proto::sgtypes::ChannelScriptPackage) -> Result<Self> {
        SimpleDeserializer::deserialize(value.payload.as_slice())
    }
}

impl From<ChannelScriptPackage> for crate::proto::sgtypes::ChannelScriptPackage {
    fn from(value: ChannelScriptPackage) -> Self {
        Self {
            payload: SimpleSerializer::serialize(&value).expect("serialize must success."),
        }
    }
}
