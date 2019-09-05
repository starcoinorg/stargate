use failure::prelude::*;
use ir_to_bytecode::parser::{parse_program};
use ir_to_bytecode::{compiler::compile_program};
use lazy_static::lazy_static;
use stdlib::{
    stdlib_modules,
};
use types::transaction::{TransactionArgument, Program, Script};
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
    Open,
    Deposit,
    Transfer,
    Withdraw,
    Close,
}

impl ChannelOp {
    pub fn values() -> Vec<ChannelOp>{
        vec![ChannelOp::Open, ChannelOp::Deposit, ChannelOp::Transfer, ChannelOp::Withdraw, ChannelOp::Close]
    }

    pub fn asset_op_values() -> Vec<ChannelOp>{
        vec![ChannelOp::Deposit, ChannelOp::Transfer, ChannelOp::Withdraw]
    }
}

impl Display for ChannelOp{

    fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
        match self{
            ChannelOp::Open => write!(f, "open"),
            ChannelOp::Deposit => write!(f, "deposit"),
            ChannelOp::Transfer => write!(f, "transfer"),
            ChannelOp::Withdraw => write!(f, "withdraw"),
            ChannelOp::Close => write!(f, "close"),
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

    pub fn encode_script(&self, args: Vec<TransactionArgument>) -> Script {
        Script::new(self.code.clone(), args)
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
pub struct AssetScriptRegistry{
    open_script: ScriptCode,
    asset_scripts: HashMap<StructTag, AssetChannelScripts>,
    close_script: ScriptCode,
}

impl AssetScriptRegistry {

    pub fn build() -> Result<Self>{
        let mut asset_scripts = HashMap::new();
        let open_script = compile_script("open.mvir")?;
        for (asset_folder, asset_tag) in ASSET_SCRIPT_FOLDERS.clone(){
            let mut scripts = HashMap::new();
            for op in ChannelOp::asset_op_values(){
                let path = format!("{}/{}.mvir", asset_folder, op);
                let script = compile_script(path.as_str())?;
                scripts.insert(op, ScriptCode::new(op,script));
            }
            asset_scripts.insert(asset_tag, AssetChannelScripts::new(scripts));
        }
        let close_script = compile_script("close.mvir")?;
        Ok(Self{
            open_script:ScriptCode::new(ChannelOp::Open, open_script),
            asset_scripts,
            close_script:ScriptCode::new(ChannelOp::Close, close_script),
         })
    }
    pub fn get_scripts(&self, coin_tag: &StructTag) -> Option<&AssetChannelScripts> {
        self.asset_scripts.get(coin_tag)
    }

    pub fn open_script(&self) -> &ScriptCode {
        &self.open_script
    }

    pub fn close_script(&self) -> &ScriptCode {
        &self.close_script
    }
}

fn compile_script(path: &str) -> Result<Vec<u8>>{
    let script_str = SCRIPTS_DIR.get_file(path).and_then(|file|file.contents_utf8()).ok_or(format_err!("Can not find script by path:{}", path))?;
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

