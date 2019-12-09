// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use anyhow::{bail, format_err, Result};
use bytecode_verifier::VerifiedModule;
use ir_to_bytecode::parser::{
    ast::{ImportDefinition, ModuleIdent},
    parse_module, parse_program, parse_script,
};
use libra_logger::prelude::*;
use libra_state_view::StateView;
use libra_types::{
    access_path::AccessPath, account_address::AccountAddress, language_storage::ModuleId,
};
use sgtypes::script_package::{ChannelScriptPackage, ScriptCode};
use std::collections::HashSet;
use stdlib::stdlib_modules;
use vm::{access::ModuleAccess, file_format::CompiledModule};

pub struct ScriptFile {
    path: PathBuf,
    contents: String,
}

impl ScriptFile {
    pub fn new(path: PathBuf, contents: String) -> Self {
        Self { path, contents }
    }

    pub fn script_name(&self) -> &str {
        self.path
            .file_stem()
            .and_then(|os_str| os_str.to_str())
            .expect("get file name should success.")
    }

    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    pub fn contents(&self) -> &str {
        self.contents.as_str()
    }

    pub fn extension(&self) -> &str {
        self.path
            .extension()
            .and_then(|os_str| os_str.to_str())
            .unwrap_or_default()
    }
}

pub trait ModuleLoader {
    fn load_module(&self, module_id: &ModuleId) -> Result<Option<Vec<u8>>>;

    fn load_compiled_module(&self, module_id: &ModuleId) -> Result<Option<CompiledModule>> {
        self.load_module(module_id).and_then(|value| match value {
            Some(value) => Ok(Some(CompiledModule::deserialize(value.as_slice())?)),
            None => Ok(None),
        })
    }

    fn load_verified_module(&self, module_id: &ModuleId) -> Result<Option<VerifiedModule>> {
        //TODO how to handle std module?
        if module_id.address() == &AccountAddress::default() {
            for module in stdlib_modules() {
                if &module.self_id() == module_id {
                    return Ok(Some(module.clone()));
                }
            }
        }
        self.load_compiled_module(module_id)
            .and_then(|module| match module {
                Some(module) => Ok(Some(VerifiedModule::new(module).map_err(
                    |(complied_module, status)| {
                        format_err!(
                            "Verified module {:?} error {:?}",
                            complied_module.self_id(),
                            status
                        )
                    },
                )?)),
                None => Ok(None),
            })
    }
}

pub struct EmptyModuleLoader {}

impl ModuleLoader for EmptyModuleLoader {
    fn load_module(&self, _module_id: &ModuleId) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
}

//TODO cache module
pub struct StateViewModuleLoader<'a> {
    state_view: &'a dyn StateView,
}

impl<'a> StateViewModuleLoader<'a> {
    pub fn new(state_view: &'a dyn StateView) -> Self {
        Self { state_view }
    }
}

impl<'a> ModuleLoader for StateViewModuleLoader<'a> {
    fn load_module(&self, module_id: &ModuleId) -> Result<Option<Vec<u8>>> {
        self.state_view
            .get(&AccessPath::code_access_path(module_id))
    }
}

pub struct Compiler<'a> {
    address: AccountAddress,
    module_loader: &'a dyn ModuleLoader,
}

impl<'a> Compiler<'a> {
    pub fn new(address: AccountAddress) -> Self {
        Self {
            address,
            module_loader: &EmptyModuleLoader {},
        }
    }

    pub fn new_with_module_loader(
        address: AccountAddress,
        module_loader: &'a dyn ModuleLoader,
    ) -> Self {
        Self {
            address,
            module_loader,
        }
    }

    pub fn load_deps(&self, dep_ids: Vec<ModuleId>) -> Result<Vec<VerifiedModule>> {
        info!("load deps: {:?}", dep_ids);
        let deps: Result<Vec<VerifiedModule>> = dep_ids
            .iter()
            .map(|module_id| {
                info!("load module: {:?}", module_id);
                self.module_loader
                    .load_verified_module(module_id)?
                    .ok_or(format_err!("Can not find module: {:?}", module_id))
            })
            .collect();
        Ok(deps?)
    }

    // tread import transaction.Module as external deps
    fn get_deps(&self, imports: &[ImportDefinition]) -> Vec<ModuleId> {
        let mut deps = HashSet::new();
        for dep in imports.iter() {
            let module_id = match &dep.ident {
                ModuleIdent::Transaction(module_name) => {
                    ModuleId::new(self.address, module_name.clone().into_inner())
                }
                ModuleIdent::Qualified(ident) => {
                    ModuleId::new(ident.address, ident.name.clone().into_inner())
                }
            };
            deps.insert(module_id);
        }
        deps.into_iter().collect()
    }

    pub fn compile_script(&self, script_str: &str) -> Result<Vec<u8>> {
        let ast_script = parse_script(script_str)?;
        let deps = self.load_deps(self.get_deps(ast_script.imports.as_slice()))?;
        let (compiled_script, _) =
            ir_to_bytecode::compiler::compile_script(self.address, ast_script, &deps)?;
        let mut byte_code = vec![];
        compiled_script.serialize(&mut byte_code)?;
        Ok(byte_code)
    }

    pub fn compile_module(&self, module_str: &str) -> Result<Vec<u8>> {
        let ast_module = parse_module(module_str)?;
        let deps = self.load_deps(ast_module.get_external_deps())?;
        let (compiled_module, _) =
            ir_to_bytecode::compiler::compile_module(self.address, ast_module, &deps)?;
        let mut byte_code = vec![];
        compiled_module.serialize(&mut byte_code)?;
        Ok(byte_code)
    }

    pub fn compile_program(&self, program_str: &str) -> Result<Vec<u8>> {
        let ast_program = parse_program(program_str)?;
        // aggragator deps
        let mut deps = ast_program.script.get_external_deps();
        let modules = ast_program.modules.clone();
        for program_module in modules {
            deps.extend_from_slice(&program_module.get_external_deps());
        }
        let deps_module = self.load_deps(deps)?;
        let (compiled_program, _) =
            ir_to_bytecode::compiler::compile_program(self.address, ast_program, &deps_module)?;
        let mut byte_code = vec![];
        for module in compiled_program.modules.into_iter() {
            module.serialize(&mut byte_code)?;
        }
        compiled_program.script.serialize(&mut byte_code)?;
        Ok(byte_code)
    }

    pub fn compile_package_with_files(
        &self,
        package_name: &str,
        script_files: Vec<ScriptFile>,
    ) -> Result<ChannelScriptPackage> {
        let mut scripts = vec![];
        info!("compile package {}", package_name);
        for file in script_files {
            let ext = file.extension();
            if ext != "mvir" {
                warn!("file {} is not a mvir file", file.path().display());
                continue;
            }
            let script_name = file.script_name();
            let script = self.compile_script(file.contents())?;
            info!("find package: {} script {}", package_name, script_name);
            scripts.push(ScriptCode::new(
                script_name.to_string(),
                file.contents().to_string(),
                script,
            ));
        }
        Ok(ChannelScriptPackage::new(package_name.to_string(), scripts))
    }

    pub fn compile_package<P: AsRef<Path>>(&self, path: P) -> Result<ChannelScriptPackage> {
        let dir_path = path.as_ref();
        if !dir_path.exists() || !dir_path.is_dir() {
            bail!("Dir {} is not a dir or not exists", dir_path.display());
        }
        let package_name = dir_path
            .file_name()
            .and_then(|os_str| os_str.to_str())
            .expect("Get dir file name should success");

        let mut script_files = vec![];
        for entry in std::fs::read_dir(dir_path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                warn!("Not supported embed dir {}.", path.display());
            } else {
                let contents = std::fs::read_to_string(path.as_path())?;
                script_files.push(ScriptFile { path, contents });
            }
        }
        self.compile_package_with_files(package_name, script_files)
    }

    pub fn compile_package_with_output<P: AsRef<Path>>(
        &self,
        path: P,
        output: P,
    ) -> Result<ChannelScriptPackage> {
        let csp = self
            .compile_package(path)
            .unwrap_or_else(|err| panic!("Unable to open file: {}", err));
        csp.dump_to(output.as_ref());
        Ok(csp)
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use libra_logger::try_init_for_testing;
    use libra_types::identifier::{IdentStr, Identifier};

    use crate::mock_module_loader::MockModuleLoader;

    use super::*;

    fn get_test_package(package_name: &str) -> PathBuf {
        let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
        crate_root.join(format!("test_scripts/{}", package_name))
    }

    #[test]
    fn test_compile() -> Result<()> {
        try_init_for_testing();
        let compiler = Compiler::new(AccountAddress::default());
        let package1_path = get_test_package("package1");
        let package = compiler.compile_package(package1_path)?;
        let script = package.get_script("empty");
        assert!(script.is_some(), "the script named empty should exist.");
        Ok(())
    }

    #[test]
    fn test_with_module_loader() -> Result<()> {
        try_init_for_testing();
        let address = AccountAddress::random();
        let module_loader = MockModuleLoader::new();
        let module_id = ModuleId::new(address, Identifier::from(IdentStr::new("Mock")?));
        module_loader.mock_empty_module(&module_id)?;

        let compiler = Compiler::new_with_module_loader(address, &module_loader);

        let package_path = get_test_package("package_with_custom_module");
        let package = compiler.compile_package(package_path)?;
        let script = package.get_script("simple");
        assert!(script.is_some(), "the script named simple should exist.");
        Ok(())
    }

    #[test]
    fn test_compile_complex_script() -> Result<()> {
        let address = AccountAddress::random();
        let module_loader = MockModuleLoader::new();

        let compiler = Compiler::new_with_module_loader(address, &module_loader);
        let package_path = get_test_package("complex_script");
        let script_src = std::fs::read_to_string(package_path.join("script.mvir").as_path())?;
        let first_bytes = compiler.compile_script(script_src.as_str())?;
        let second_bytes = compiler.compile_script(script_src.as_str())?;
        assert_eq!(first_bytes, second_bytes);
        Ok(())
    }
}

pub mod mock_module_loader;
