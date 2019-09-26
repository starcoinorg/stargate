use std::path::{Path, PathBuf};
use failure::prelude::*;
use ir_to_bytecode::compiler::compile_program;
use ir_to_bytecode::parser::parse_program;
use logger::prelude::*;
use star_types::script_package::{ChannelScriptPackage, ScriptCode};
use stdlib::stdlib_modules;
use types::account_address::AccountAddress;

pub struct Compiler {}

impl Compiler {}

pub struct ScriptFile {
    path: PathBuf,
    contents: String,
}

impl ScriptFile {

    pub fn new(path: PathBuf, contents: String) -> Self{
        Self{
            path,
            contents
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

pub fn compile_script(script_str: &str) -> Result<Vec<u8>> {
    let ast_program = parse_program(script_str)?;
    let compiled_program =
        compile_program(AccountAddress::default(), ast_program, stdlib_modules())?;
    let mut script_bytes = vec![];
    compiled_program
        .script
        .serialize(&mut script_bytes)?;
    Ok(script_bytes)
}

pub fn compile_package_with_files(package_name: &str, script_files: Vec<ScriptFile>) -> Result<ChannelScriptPackage> {
    let mut scripts = vec![];
    info!("compile package {}", package_name);
    for file in script_files {
        let ext = file.extension();
        if ext != "mvir" {
            warn!("file {} is not a mvir file", file.path().display());
            continue;
        }
        let script_name = file.script_name();
        let script = compile_script(file.contents())?;
        info!("find package: {} script {}", package_name, script_name);
        scripts.push(ScriptCode::new(script_name.to_string(), file.contents().to_string(), script));
    }
    Ok(ChannelScriptPackage::new(package_name.to_string(), scripts))
}

pub fn compile_package<P: AsRef<Path>>(path: P) -> Result<ChannelScriptPackage> {
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
    compile_package_with_files(package_name, script_files)
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use crate::compile_package;

    use super::*;
    use logger::init_for_e2e_testing;

    #[test]
    fn test_compile() -> Result<()> {
        init_for_e2e_testing();
        let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let package1_path = crate_root.join("test_scripts/package1");
        let package = compile_package(package1_path.as_path())?;
        let script = package.get_script("empty");
        assert!(script.is_some(), "the script named empty should exist.");
        Ok(())
    }
}
