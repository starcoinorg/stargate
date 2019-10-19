use executable_helpers::helpers::setup_executable;
use logger::prelude::*;
use slog_scope::GlobalLoggerGuard;
use std::path::PathBuf;

use config::config::NodeConfig;
use libra_node::main_node::LibraHandle;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(about = "Libra Node")]
pub struct Args {
    #[structopt(short = "f", long, parse(from_os_str))]
    /// Path to NodeConfig
    pub config: Option<PathBuf>,
    #[structopt(short = "d", long)]
    /// Disable logging
    pub no_logging: bool,
}

pub fn run_node(args: Args) -> (LibraHandle, NodeConfig, Option<GlobalLoggerGuard>) {
    let (mut config, logger) =
        setup_executable(args.config.as_ref().map(PathBuf::as_path), args.no_logging);

    debug!("config : {:?}", config);
    crate::star_chain_client::genesis_blob(&config);
    (
        libra_node::main_node::setup_environment(&mut config),
        config,
        logger,
    )
}
