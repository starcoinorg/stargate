use std::collections::HashMap;
use std::fmt::{Display, Formatter};

use include_dir::Dir;

use failure::prelude::*;
use ir_to_bytecode::{compiler::compile_program};
use ir_to_bytecode::parser::parse_program;
use lazy_static::lazy_static;
use star_types::channel_transaction::ChannelOp;
use stdlib::stdlib_modules;
use types::account_address::AccountAddress;
use types::account_config::coin_struct_tag;
use types::language_storage::StructTag;
use types::transaction::{Program, Script, TransactionArgument};
use logger::prelude::*;

static SCRIPTS_DIR: Dir = include_dir!("scripts");

pub static DEFAULT_PACKAGE: &str = "libra";

lazy_static! {
    static ref ASSET_SCRIPT_FOLDERS:Vec<(&'static str,StructTag)> = vec![("libra", coin_struct_tag())];
}

#[derive(Debug, Clone)]
pub struct ScriptCode {
    name:String,
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

    pub fn encode_program(&self, args: Vec<TransactionArgument>) -> Program {
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
pub struct ChannelOperatorScripts(HashMap<String, ScriptCode>);

impl ChannelOperatorScripts {
    pub fn new(scripts: HashMap<String, ScriptCode>) -> Self {
        Self(scripts)
    }

    pub fn get_script(&self, name: &str) -> Option<&ScriptCode> {
        self.0.get(name)
    }
}

#[derive(Debug, Clone)]
pub struct ChannelScriptRegistry {
    open_script: ScriptCode,
    asset_scripts: HashMap<String, ChannelOperatorScripts>,
    close_script: ScriptCode,
}

impl ChannelScriptRegistry {
    pub fn build() -> Result<Self> {
        let mut asset_scripts = HashMap::new();
        let open_script = compile_script_with_file("open.mvir")?;
        info!("{:?}", SCRIPTS_DIR.dirs());
        for dir in SCRIPTS_DIR.dirs() {
            let mut scripts = HashMap::new();
            let package_name = dir.path().to_str().unwrap();
            info!("scan package {}", package_name);
            for file in dir.files() {
                let ext = file.path().extension().unwrap_or_default();
                if ext != "mvir"{
                    warn!("file {} is not a mvir file", file.path().display());
                    continue;
                }
                //TODO handle unwrap
                let script_name = file.path().file_stem().unwrap().to_str().unwrap();
                let script = compile_script(file.contents_utf8().unwrap())?;
                info!("find package: {} script {}", package_name, script_name);
                scripts.insert(script_name.to_string(), ScriptCode::new(script_name.to_string(), script));
            }
            asset_scripts.insert(package_name.to_string(), ChannelOperatorScripts(scripts));
        }
        let close_script = compile_script_with_file("close.mvir")?;
        Ok(Self {
            open_script: ScriptCode::new(ChannelOp::Open.to_string(), open_script),
            asset_scripts,
            close_script: ScriptCode::new(ChannelOp::Close.to_string(), close_script),
        })
    }
    pub fn get_script(&self, package_name: &str, script_name: &str) -> Option<&ScriptCode> {
        self.asset_scripts.get(package_name).
            and_then(|package|package.get_script(script_name))
    }

    pub fn open_script(&self) -> &ScriptCode {
        &self.open_script
    }

    pub fn close_script(&self) -> &ScriptCode {
        &self.close_script
    }
}
fn compile_script_with_file(path: &str) -> Result<Vec<u8>> {
    let script_str = SCRIPTS_DIR.get_file(path).and_then(|file| file.contents_utf8()).ok_or(format_err!("Can not find script by path:{}", path))?;
    compile_script(script_str)
}
fn compile_script(script_str: &str) -> Result<Vec<u8>> {

    let ast_program = parse_program(script_str)?;
    let compiled_program =
        compile_program(AccountAddress::default(), ast_program, stdlib_modules())?;
    let mut script_bytes = vec![];
    compiled_program
        .script
        .serialize(&mut script_bytes)?;
    Ok(script_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use logger::init_for_e2e_testing;

    #[test]
    fn test_scripts_include() {
        SCRIPTS_DIR.find("*.mvir").unwrap().next().unwrap();
    }

    #[test]
    fn test_compile_script() {
        init_for_e2e_testing();
        let registry = ChannelScriptRegistry::build().unwrap();
        registry.get_script("libra", "transfer").unwrap();
    }
}

