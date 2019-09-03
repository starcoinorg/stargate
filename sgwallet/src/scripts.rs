use failure::prelude::*;
use ir_to_bytecode::parser::{parse_program};
use ir_to_bytecode::{compiler::compile_program};
use lazy_static::lazy_static;
use stdlib::{
    stdlib_modules,
};
use types::transaction::{TransactionArgument, Program};
use std::collections::HashMap;
use types::account_config::coin_struct_tag;
use types::account_address::AccountAddress;
use types::language_storage::StructTag;
use std::fmt::{Display, Formatter};
use include_dir::Dir;


static SCRIPTS_DIR:Dir = include_dir!("scripts");

lazy_static! {
    static ref ASSET_SCRIPT_FOLDERS:Vec<(&'static str,StructTag)> = vec![("libra", coin_struct_tag())];
}
#[derive(Debug, Eq, PartialEq, Hash, Clone, Copy)]
pub enum ChannelOp{
    Fund,
    Transfer,
    Withdraw,
}

impl ChannelOp {
    pub fn values() -> Vec<ChannelOp>{
        vec![ChannelOp::Fund, ChannelOp::Transfer, ChannelOp::Withdraw]
    }
}

impl Display for ChannelOp{

    fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
        match self{
            ChannelOp::Fund => write!(f, "fund"),
            ChannelOp::Transfer => write!(f, "transfer"),
            ChannelOp::Withdraw => write!(f, "withdraw"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScriptCode{
    script_type: ChannelOp,
    code: Vec<u8>,
}

impl ScriptCode {
    pub fn new(script_type:ChannelOp, code: Vec<u8>) -> Self{
        Self{
            script_type,
            code,
        }
    }

    pub fn code(&self)-> &Vec<u8>{
        &self.code
    }

    pub fn encode_program(&self, args: Vec<TransactionArgument>) -> Program{
        //TODO check args
        Program::new(
            self.code.clone(),
            vec![],
            args,
        )
    }
}

#[derive(Debug, Clone)]
pub struct AssetChannelScripts(HashMap<ChannelOp,ScriptCode>);

impl AssetChannelScripts {

    pub fn new(scripts: HashMap<ChannelOp,ScriptCode>) -> Self{
        Self(scripts)
    }

    pub fn get_script(&self, op: ChannelOp) -> &ScriptCode{
        self.0.get(&op).expect(format!("Script type:{} must exist.",op).as_str())
    }
}

#[derive(Debug, Clone)]
pub struct AssetScriptRegistry(HashMap<StructTag, AssetChannelScripts>);

impl AssetScriptRegistry {

    pub fn build() -> Result<Self>{
        let mut registry = HashMap::new();
        for (asset_folder, asset_tag) in ASSET_SCRIPT_FOLDERS.clone(){
            let mut scripts = HashMap::new();
            for op in ChannelOp::values(){
                let script = compile_script(asset_folder, &op)?;
                scripts.insert(op, ScriptCode::new(op,script));
            }
            registry.insert(asset_tag, AssetChannelScripts::new(scripts));
        }
        Ok(Self(registry))
    }
    pub fn get_scripts(&self, coin_tag: &StructTag) -> Option<&AssetChannelScripts> {
        self.0.get(coin_tag)
    }
}

fn compile_script(asset_folder:&str, op: &ChannelOp) -> Result<Vec<u8>>{
    let path = format!("{}/{}.mvir", asset_folder, op);
    let script_str = SCRIPTS_DIR.get_file(path.as_str()).and_then(|file|file.contents_utf8()).ok_or(format_err!("Can not find script by path:{}", path))?;
    let ast_program  = parse_program(script_str)?;
    let compiled_program =
        compile_program(AccountAddress::default(), ast_program, stdlib_modules())?;
    let mut script_bytes = vec![];
    compiled_program
        .script
        .serialize(&mut script_bytes)?;
    Ok(script_bytes)
}

#[cfg(test)]
mod tests{
    use super::*;

    #[test]
    fn test_scripts_include(){
        SCRIPTS_DIR.find("*.mvir").unwrap().next().unwrap();
    }
    #[test]
    fn test_compile_script(){
        let registry = AssetScriptRegistry::build().unwrap();
        registry.get_scripts(&coin_struct_tag()).unwrap();
    }
}

