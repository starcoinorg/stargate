use std::path::{Path, PathBuf};

use bytecode_verifier::VerifiedModule;
use sgchain::star_chain_client::ChainClient;
use sgchain::client_state_view::ClientStateView;
use failure::prelude::*;
use ir_to_bytecode::compiler::compile_program;
use ir_to_bytecode::parser::{parse_program, parse_script, parse_module};
use logger::prelude::*;
use star_types::script_package::{ChannelScriptPackage, ScriptCode};
use state_view::StateView;
use stdlib::stdlib_modules;
use types::access_path::AccessPath;
use types::account_address::AccountAddress;
use types::language_storage::ModuleId;
use vm::{
    access::ScriptAccess,
    file_format::{CompiledModule, CompiledScript},
};
use vm::access::ModuleAccess;

pub struct ScriptFile {
    path: PathBuf,
    contents: String,
}

impl ScriptFile {
    pub fn new(path: PathBuf, contents: String) -> Self {
        Self {
            path,
            contents,
        }
    }

    pub fn script_name(&self) -> &str {
        self.path.file_stem().and_then(|os_str| os_str.to_str()).expect("get file name should success.")
    }

    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    pub fn contents(&self) -> &str {
        self.contents.as_str()
    }

    pub fn extension(&self) -> &str {
        self.path.extension().and_then(|os_str| os_str.to_str()).unwrap_or_default()
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
        if module_id.address() == &AccountAddress::default(){
            for module in stdlib_modules(){
                if &module.self_id() == module_id{
                    return Ok(Some(module.clone()))
                }
            }
        }
        self.load_compiled_module(module_id).and_then(|module| match module {
            Some(module) => Ok(Some(VerifiedModule::new(module).map_err(|(complied_module, status)| {
                format_err!("Verified module {:?} error", complied_module.self_id())
            })?)),
            None => Ok(None)
        })
    }
}

pub struct EmptyModuleLoader {
}

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
        Self {
            state_view
        }
    }
}

impl<'a> ModuleLoader for StateViewModuleLoader<'a> {
    fn load_module(&self, module_id: &ModuleId) -> Result<Option<Vec<u8>>> {
        self.state_view.get(&AccessPath::code_access_path(module_id))
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
            module_loader: &EmptyModuleLoader{}
        }
    }

    pub fn new_with_module_loader(address: AccountAddress, module_loader: &'a dyn ModuleLoader) -> Self {
        Self {
            address,
            module_loader
        }
    }

    pub fn load_deps(&self, dep_ids: Vec<ModuleId>) -> Result<Vec<VerifiedModule>> {
        let deps: Result<Vec<VerifiedModule>> = dep_ids.iter()
            .map(|module_id| {
                info!("load module: {:?}", module_id);
                self.module_loader.load_verified_module(module_id)?.ok_or(format_err!("Can not find module: {:?}", module_id))
            })
            .collect();
        Ok(deps?)
    }

    pub fn compile_script(&self, script_str: &str) -> Result<Vec<u8>> {
        let ast_script = parse_script(script_str)?;
        let deps = self.load_deps(ast_script.get_external_deps())?;
        let compiled_script =
            ir_to_bytecode::compiler::compile_script(self.address, ast_script, &deps)?;
        let mut byte_code = vec![];
        compiled_script
            .serialize(&mut byte_code)?;
        Ok(byte_code)
    }

    pub fn compile_module(&self, module_str: &str) -> Result<Vec<u8>> {
        let ast_module = parse_module(module_str)?;
        let deps = self.load_deps(ast_module.get_external_deps())?;
        let compiled_module =
            ir_to_bytecode::compiler::compile_module(self.address, ast_module, &deps)?;
        let mut byte_code = vec![];
        compiled_module
            .serialize(&mut byte_code)?;
        Ok(byte_code)
    }

    pub fn compile_package_with_files(&self, package_name: &str, script_files: Vec<ScriptFile>) -> Result<ChannelScriptPackage> {
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
            scripts.push(ScriptCode::new(script_name.to_string(), file.contents().to_string(), script));
        }
        Ok(ChannelScriptPackage::new(package_name.to_string(), scripts))
    }

    pub fn compile_package<P: AsRef<Path>>(&self, path: P) -> Result<ChannelScriptPackage> {
        let dir_path = path.as_ref();
        if !dir_path.exists() || !dir_path.is_dir() {
            bail!("Dir {} is not a dir or not exists", dir_path.display());
        }
        let package_name = dir_path.file_name().and_then(|os_str| os_str.to_str()).expect("Get dir file name should success");

        let mut script_files = vec![];
        for entry in std::fs::read_dir(dir_path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                warn!("Not supported embed dir {}.", path.display());
            } else {
                let contents = std::fs::read_to_string(path.as_path())?;
                script_files.push(ScriptFile {
                    path,
                    contents,
                });
            }
        }
        self.compile_package_with_files(package_name, script_files)
    }
}


#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use logger::init_for_e2e_testing;

    use super::*;
    use crate::mock_module_loader::MockModuleLoader;
    use types::identifier::{Identifier, IdentStr};

    fn get_test_package(package_name:&str) -> PathBuf{
        let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
        crate_root.join(format!("test_scripts/{}", package_name))
    }

    #[test]
    fn test_compile() -> Result<()> {
        init_for_e2e_testing();
        let compiler = Compiler::new(AccountAddress::default());
        let package1_path = get_test_package("package1");
        let package = compiler.compile_package(package1_path)?;
        let script = package.get_script("empty");
        assert!(script.is_some(), "the script named empty should exist.");
        Ok(())
    }

    #[test]
    fn test_with_module_loader() -> Result<()> {
        init_for_e2e_testing();
        let module_loader = MockModuleLoader::new();
        let module_id = ModuleId::new(AccountAddress::default(), Identifier::from(IdentStr::new("Mock")?));
        module_loader.mock_empty_module(&module_id)?;
        let address = AccountAddress::random();
        let compiler = Compiler::new_with_module_loader(address, &module_loader);

        let package_path = get_test_package("package_with_custom_module");
        let package = compiler.compile_package(package_path)?;
        let script = package.get_script("simple");
        assert!(script.is_some(), "the script named simple should exist.");
        Ok(())
    }
}

pub mod mock_module_loader;