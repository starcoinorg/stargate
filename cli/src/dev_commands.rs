// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{client_proxy::ClientProxy, commands::*};

/// Major command for account related operations.
pub struct DevCommand {}

impl Command for DevCommand {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["dev"]
    }
    fn get_description(&self) -> &'static str {
        "Local move development"
    }
    fn execute(&self, client: &mut ClientProxy, params: &[&str]) {
        let commands: Vec<Box<dyn Command>> = vec![
            Box::new(DevCommandCompile {}),
            Box::new(DevCommandPublish {}),
            Box::new(DevCommandExecute {}),
            Box::new(DevCommandPackageDeploy{}),
            Box::new(DevCommandExecuteInstalledScript{}),
        ];
        subcommand_execute(&params[0], commands, client, &params[1..]);
    }
}

/// Sub command to compile move program
pub struct DevCommandCompile {}

impl Command for DevCommandCompile {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["compile", "c"]
    }
    fn get_params_help(&self) -> &'static str {
        "<file_path> [is_module (default=false)] [output_file_path (compile into tmp file by default)]"
    }
    fn get_description(&self) -> &'static str {
        "Compile move program"
    }
    fn execute(&self, client: &mut ClientProxy, params: &[&str]) {
        if params.len() < 2 || params.len() > 4 {
            println!("Invalid number of arguments for compilation");
            return;
        }
        println!(">> Compiling program");
        match client.compile_program(params) {
            Ok(path) => println!("Successfully compiled a program at {}", path),
            Err(e) => println!("{}", e),
        }
    }
}

/// Sub command to publish move resource
pub struct DevCommandPublish {}

impl Command for DevCommandPublish {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["publish", "p"]
    }

    fn get_params_help(&self) -> &'static str {
        "<compiled_module_path>"
    }

    fn get_description(&self) -> &'static str {
        "Publish move module on-chain"
    }

    fn execute(&self, client: &mut ClientProxy, params: &[&str]) {
        if params.len() != 2 {
            println!("Invalid number of arguments to publish module");
            return;
        }
        match client.publish_module(params) {
            Ok(_) => println!("Successfully published module"),
            Err(e) => println!("{}", e),
        }
    }
}

/// Sub command to execute custom move script
pub struct DevCommandExecute {}

impl Command for DevCommandExecute {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["execute", "e"]
    }

    fn get_params_help(&self) -> &'static str {
        "<compiled_module_path> [parameters]"
    }

    fn get_description(&self) -> &'static str {
        "Execute custom move script"
    }

    fn execute(&self, client: &mut ClientProxy, params: &[&str]) {
        if params.len() < 2 {
            println!("Invalid number of arguments to execute script");
            return;
        }
        match client.execute_script(params) {
            Ok(_) => println!("Successfully finished execution"),
            Err(e) => println!("{}", e),
        }
    }
}

/// Sub command to compile move program
pub struct DevCommandPackageDeploy {}

impl Command for DevCommandPackageDeploy {
    fn get_aliases(&self) -> Vec<&'static str> {
        vec!["package deploy", "pd"]
    }
    fn get_params_help(&self) -> &'static str {
        "<dir_path> <module_file_name> <scripts_dir_name>"
    }
    fn get_description(&self) -> &'static str {
        "Deploy move package"
    }
    fn execute(&self, client: &mut ClientProxy, params: &[&str]) {
        if params.len() < 2 {
            println!("Invalid number of arguments for compilation");
            return;
        }
        println!(">> Deploy program");
        match client.deploy_package(params) {
            Ok(path) => println!("Successfully deployed package "),
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
        "remote_address package_name script_name args..."
    }
    fn get_description(&self) -> &'static str {
        "Deploy move package"
    }
    fn execute(&self, client: &mut ClientProxy, params: &[&str]) {
        if params.len() < 3 {
            println!("Invalid number of arguments for compilation");
            return;
        }
        println!(">> Deploy program");
        match client.execute_installed_script(params) {
            Ok(path) => println!("Successfully deployed package "),
            Err(e) => println!("{}", e),
        }
    }
}
