use crate::client_proxy::ClientProxy;
use std::sync::Arc;
use std::collections::HashMap;

pub fn get_commands() -> (
    Vec<Arc<dyn Command>>,
    HashMap<&'static str, Arc<dyn Command>>,
) {
    let commands: Vec<Arc<dyn Command>> = vec![];
    let mut alias_to_cmd = HashMap::new();
    for command in &commands {
        for alias in command.get_aliases() {
            alias_to_cmd.insert(alias, Arc::clone(command));
        }
    }
    (commands, alias_to_cmd)
}

/// Parse a cmd string, the first element in the returned vector is the command to run
pub fn parse_cmd(cmd_str: &str) -> Vec<&str> {
    let input = &cmd_str[..];
    input.trim().split(' ').map(str::trim).collect()
}

pub trait Command {
    /// all commands and aliases this command support.
    fn get_aliases(&self) -> Vec<&'static str>;
    /// string that describes params.
    fn get_params_help(&self) -> &'static str {
        ""
    }
    /// string that describes what the command does.
    fn get_description(&self) -> &'static str;
    /// code to execute.
    fn execute(&self, client: &mut ClientProxy, params: &[&str]);
}