use executable_helpers::helpers::setup_executable;
use libra_config::config::{NodeConfig, NodeConfigHelpers};
use libra_logger::prelude::*;
use libra_node::main_node::LibraHandle;
use slog_scope::GlobalLoggerGuard;
use std::path::Path;
pub fn run_node(
    config: Option<&Path>,
    no_logging: bool,
    random_ports: bool,
) -> (NodeConfig, Option<GlobalLoggerGuard>, LibraHandle) {
    let (mut config, logger) = setup_executable(config, no_logging);
    if random_ports {
        NodeConfigHelpers::randomize_config_ports(&mut config);
    }
    debug!("config : {:?}", config);
    crate::star_chain_client::genesis_blob(&config);
    let handler = libra_node::main_node::setup_environment(&mut config);
    (config, logger, handler)
}
