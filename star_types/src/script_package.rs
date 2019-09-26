use serde::{Deserialize, Serialize};

use canonical_serialization::{CanonicalDeserialize, CanonicalDeserializer, CanonicalSerialize, CanonicalSerializer, SimpleDeserializer, SimpleSerializer};
use failure::prelude::*;
use types::transaction::{Script, TransactionArgument};
use proto_conv::{FromProto, IntoProto};

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

impl CanonicalSerialize for ScriptCode {
    fn serialize(&self, serializer: &mut impl CanonicalSerializer) -> Result<()> {
        serializer.encode_string(self.name.as_str())?
            .encode_bytes(self.code.as_slice())?;
        Ok(())
    }
}

impl CanonicalDeserialize for ScriptCode {
    fn deserialize(deserializer: &mut impl CanonicalDeserializer) -> Result<Self> where
        Self: Sized {
        let name = deserializer.decode_string()?;
        let code = deserializer.decode_bytes()?;
        Ok(Self {
            name,
            code,
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
        self.scripts.iter().find(|script| script.name.as_str() == name)
    }
}

impl CanonicalSerialize for ChannelScriptPackage {
    fn serialize(&self, serializer: &mut impl CanonicalSerializer) -> Result<()> {
        serializer.encode_string(self.package_name.as_str())?
            .encode_vec(&self.scripts)?;
        Ok(())
    }
}

impl CanonicalDeserialize for ChannelScriptPackage {

    fn deserialize(deserializer: &mut impl CanonicalDeserializer) -> Result<Self> where
        Self: Sized {
        let package_name = deserializer.decode_string()?;
        let scripts = deserializer.decode_vec()?;
        Ok(Self{
            package_name,
            scripts
        })
    }
}

impl FromProto for ChannelScriptPackage {
    type ProtoType = crate::proto::script_package::ChannelScriptPackage;

    fn from_proto(mut object: Self::ProtoType) -> Result<Self> {
        let bytes = object.take_payload();
        Ok(SimpleDeserializer::deserialize(bytes.as_slice())?)
    }
}

impl IntoProto for ChannelScriptPackage {
    type ProtoType = crate::proto::script_package::ChannelScriptPackage;

    fn into_proto(self) -> Self::ProtoType {
        let mut out = Self::ProtoType::new();
        out.set_payload(SimpleSerializer::serialize(&self).expect("serialize must success."));
        out
    }
}
