use std::collections::HashMap;
use std::fmt::{Display, Formatter};

use atomic_refcell::AtomicRefCell;
use include_dir::Dir;

use failure::prelude::*;
use ir_to_bytecode::{compiler::compile_program};
use ir_to_bytecode::parser::parse_program;
use lazy_static::lazy_static;
use logger::prelude::*;
use sgcompiler::{compile_package_with_files, ScriptFile, compile_script};
use star_types::channel_transaction::ChannelOp;
use star_types::script_package::{ChannelScriptPackage, ScriptCode};
use stdlib::stdlib_modules;
use types::account_address::AccountAddress;
use types::account_config::coin_struct_tag;
use types::language_storage::StructTag;
use types::transaction::{Program, Script, TransactionArgument};

static SCRIPTS_DIR: Dir = include_dir!("scripts");

pub static DEFAULT_PACKAGE: &str = "libra";

lazy_static! {
    static ref ASSET_SCRIPT_FOLDERS:Vec<(&'static str,StructTag)> = vec![("libra", coin_struct_tag())];
}


#[derive(Debug, Clone)]
pub struct PackageRegistry {
    open_script: ScriptCode,
    packages: AtomicRefCell<HashMap<String, ChannelScriptPackage>>,
    close_script: ScriptCode,
}

impl PackageRegistry {
    pub fn build() -> Result<Self> {
        let mut packages = HashMap::new();
        let open_script = compile_script_with_file("open.mvir")?;
        let close_script = compile_script_with_file("close.mvir")?;
        info!("{:?}", SCRIPTS_DIR.dirs());
        for dir in SCRIPTS_DIR.dirs() {
            let package = compile_package(dir)?;
            packages.insert(package.package_name().to_string(), package);
        }
        Ok(Self {
            open_script: ScriptCode::new(ChannelOp::Open.to_string(), open_script),
            packages: AtomicRefCell::new(packages),
            close_script: ScriptCode::new(ChannelOp::Close.to_string(), close_script),
        })
    }
    pub fn get_script(&self, package_name: &str, script_name: &str) -> Option<ScriptCode> {
        self.packages.borrow().get(package_name).
            and_then(|package| package.get_script(script_name).cloned())
    }

    pub fn install_package(&self, package: ChannelScriptPackage) -> Result<()> {
        if self.packages.borrow().contains_key(package.package_name()) {
            bail!("package with name:{} exist", package.package_name());
        }
        self.packages.borrow_mut().insert(package.package_name().to_string(), package);
        Ok(())
    }

    pub fn open_script(&self) -> ScriptCode {
        self.open_script.clone()
    }

    pub fn close_script(&self) -> ScriptCode {
        self.close_script.clone()
    }
}

fn compile_script_with_file(path: &str) -> Result<Vec<u8>> {
    let script_str = SCRIPTS_DIR.get_file(path).and_then(|file| file.contents_utf8()).ok_or(format_err!("Can not find script by path:{}", path))?;
    compile_script(script_str)
}

fn compile_package(dir: &Dir) -> Result<ChannelScriptPackage> {
    let package_name = dir.path().to_str().unwrap();
    let script_files = dir.files().iter()
        .map(|file| ScriptFile::new(file.path().to_path_buf(), file.contents_utf8().expect("script contents must is string").to_string())).collect();
    compile_package_with_files(package_name, script_files)
}


#[cfg(test)]
mod tests {
    use logger::init_for_e2e_testing;

    use super::*;

    #[test]
    fn test_scripts_include() {
        SCRIPTS_DIR.find("*.mvir").unwrap().next().unwrap();
    }

    #[test]
    fn test_compile_script() {
        init_for_e2e_testing();
        let registry = PackageRegistry::build().unwrap();
        registry.get_script("libra", "transfer").unwrap();
    }
}

