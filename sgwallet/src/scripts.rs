// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use atomic_refcell::AtomicRefCell;
use include_dir::Dir;

use failure::prelude::*;

use lazy_static::lazy_static;
use libra_logger::prelude::*;
use sgcompiler::{Compiler, ScriptFile};
use sgtypes::{
    channel_transaction::ChannelOp,
    script_package::{ChannelScriptPackage, ScriptCode},
};

use libra_types::transaction::{Script, TransactionArgument};
use libra_types::{
    account_address::AccountAddress, account_config::coin_struct_tag, language_storage::StructTag,
};

static SCRIPTS_DIR: Dir = include_dir!("scripts");

pub static DEFAULT_PACKAGE: &str = "libra";

lazy_static! {
    static ref ASSET_SCRIPT_FOLDERS: Vec<(&'static str, StructTag)> =
        vec![("libra", coin_struct_tag())];
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
        let compiler = Compiler::new(AccountAddress::default());
        let open_script_source = get_file_contents("open.mvir")?;
        let open_script = compiler.compile_script(open_script_source)?;
        let close_script_source = get_file_contents("close.mvir")?;
        let close_script = compiler.compile_script(close_script_source)?;
        info!("{:?}", SCRIPTS_DIR.dirs());
        for dir in SCRIPTS_DIR.dirs() {
            let package_name = dir.path().to_str().unwrap();
            let script_files = dir
                .files()
                .iter()
                .map(|file| {
                    ScriptFile::new(
                        file.path().to_path_buf(),
                        file.contents_utf8()
                            .expect("script contents must is string")
                            .to_string(),
                    )
                })
                .collect();
            let package = compiler.compile_package_with_files(package_name, script_files)?;
            packages.insert(package.package_name().to_string(), package);
        }
        Ok(Self {
            open_script: ScriptCode::new(
                ChannelOp::Open.to_string(),
                open_script_source.to_string(),
                open_script,
            ),
            packages: AtomicRefCell::new(packages),
            close_script: ScriptCode::new(
                ChannelOp::Close.to_string(),
                close_script_source.to_string(),
                close_script,
            ),
        })
    }

    pub fn get_package(&self, package_name: &str) -> Option<ChannelScriptPackage> {
        self.packages.borrow().get(package_name).cloned()
    }

    pub fn packages(&self) -> Vec<ChannelScriptPackage> {
        self.packages
            .borrow()
            .iter()
            .map(|(_, v)| v.clone())
            .collect()
    }

    pub fn get_script(&self, package_name: &str, script_name: &str) -> Option<ScriptCode> {
        self.packages
            .borrow()
            .get(package_name)
            .and_then(|package| package.get_script(script_name).cloned())
    }

    pub fn install_package(&self, package: ChannelScriptPackage) -> Result<()> {
        if self.packages.borrow().contains_key(package.package_name()) {
            bail!("package with name:{} exist", package.package_name());
        }
        self.packages
            .borrow_mut()
            .insert(package.package_name().to_string(), package);
        Ok(())
    }

    pub fn open_script(&self) -> ScriptCode {
        self.open_script.clone()
    }

    pub fn close_script(&self) -> ScriptCode {
        self.close_script.clone()
    }

    pub fn channel_op_to_script(
        &self,
        channel_op: &ChannelOp,
        args: Vec<TransactionArgument>,
    ) -> Result<Script> {
        let script_code = match channel_op {
            ChannelOp::Open => self.open_script(),
            ChannelOp::Close => self.close_script(),
            ChannelOp::Execute {
                package_name,
                script_name,
            } => self
                .get_script(package_name, script_name)
                .ok_or(format_err!(
                    "Can not find script by package {} and script name {}",
                    package_name,
                    script_name
                ))?,
            ChannelOp::Action { .. } => bail!("Action is not supported by registry"),
        };
        let script = script_code.encode_script(args);
        Ok(script)
    }
}

fn get_file_contents(path: &str) -> Result<&str> {
    SCRIPTS_DIR
        .get_file(path)
        .and_then(|file| file.contents_utf8())
        .ok_or(format_err!("Can not find script by path:{}", path))
}

#[cfg(test)]
mod tests {
    use libra_logger::try_init_for_testing;

    use super::*;

    #[test]
    fn test_scripts_include() {
        SCRIPTS_DIR.find("*.mvir").unwrap().next().unwrap();
    }

    #[test]
    fn test_compile_script() {
        try_init_for_testing();
        let registry = PackageRegistry::build().unwrap();
        let package = registry.get_package("libra").unwrap();
        println!("{}", package);
        registry.get_script("libra", "transfer").unwrap();
    }
}
