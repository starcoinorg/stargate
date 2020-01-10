// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{commands::*, sg_client_proxy::SGClientProxy};

/// Major command for account related operations.
pub struct DevCommand {}

impl Command for DevCommand {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["dev"]
    }
    fn get_description(&self) -> &'static str {
        "Local move development"
    }
    fn execute(&self, client: &mut SGClientProxy, params: &[&str]) {
        let commands: Vec<Box<dyn Command>> = vec![
            Box::new(DevCommandDeployModule {}),
            Box::new(DevCommandInstallPackage {}),
            Box::new(DevCommandExecuteInstalledScript {}),
        ];
        subcommand_execute(&params[0], commands, client, &params[1..]);
    }
}

/// Sub command to compile move program
pub struct DevCommandDeployModule {}

impl Command for DevCommandDeployModule {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["deploy module", "dm"]
    }

    fn get_params_help(&self) -> &'static str {
        "<module_path> "
    }

    fn get_description(&self) -> &'static str {
        "Deploy move package"
    }

    fn execute(&self, client: &mut SGClientProxy, params: &[&str]) {
        if params.len() < 3 {
            println!("Invalid number of arguments for compilation");
            return;
        }
        println!(">> Deploy module");
        match client.deploy_module(params) {
            Ok(resp) => println!("Successfully deployed package {:?}", resp),
            Err(e) => println!("{}", e),
        }
    }
}

pub struct DevCommandInstallPackage {}

impl Command for DevCommandInstallPackage {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["install package", "ip"]
    }

    fn get_params_help(&self) -> &'static str {
        "<package_file_path> | <dir_path>"
    }

    fn get_description(&self) -> &'static str {
        "Install package from package_file_path, or compile and install the package from dir_path"
    }

    fn execute(&self, client: &mut SGClientProxy, params: &[&str]) {
        if params.len() < 2 {
            println!("Invalid number of arguments for compilation");
            return;
        }
        println!(">> Install script");
        match client.install_script(params) {
            Ok(_path) => println!("Successfully deployed package "),
            Err(e) => println!("{}", e),
        }
    }
}

/// Sub command to compile move program
pub struct DevCommandExecuteInstalledScript {}

impl Command for DevCommandExecuteInstalledScript {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["package execute", "pe"]
    }

    fn get_params_help(&self) -> &'static str {
        "remote_address package_name script_name force_execute args..."
    }

    fn get_description(&self) -> &'static str {
        "Deploy move package"
    }

    fn execute(&self, client: &mut SGClientProxy, params: &[&str]) {
        if params.len() < 4 {
            println!("Invalid number of arguments for compilation");
            return;
        }
        println!(">> Execute script");
        match client.execute_installed_script(params) {
            Ok(_path) => println!("Successfully execute script "),
            Err(e) => println!("{}", e),
        }
    }
}
