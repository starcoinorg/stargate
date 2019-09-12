use grpc_helpers::spawn_service_thread;
use super::chain_service::ChainService;
use signal_hook;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::runtime::{TaskExecutor, Runtime};

pub struct ServiceConfig {
    pub service_name: String,
    pub address: String,
    pub port: u16,
    pub path: Option<String>,
}

pub struct ChainNode {
    config: ServiceConfig,
}

impl ChainNode {
    pub fn new(config: ServiceConfig) -> ChainNode {
        ChainNode { config }
    }

    pub fn run(&self) -> () {
        println!("{}", "Starting chain Service");
        let mut rt = Runtime::new().unwrap();
        let exe = rt.executor();
        let service = star_types::proto::chain_grpc::create_chain(ChainService::new(&exe, &self.config.path));
        let _chain_handle = spawn_service_thread(
            service,
            self.config.address.clone(),
            self.config.port.clone(),
            self.config.service_name.clone(),
        );

        println!("{}", "Started chain Service");
        do_exit();
        rt.shutdown_now();
    }
}

fn do_exit() {
    let term = Arc::new(AtomicBool::new(false));
    for signal in &[
        signal_hook::SIGTERM,
        signal_hook::SIGINT,
        signal_hook::SIGHUP,
    ] {
        let term_clone = Arc::clone(&term);
        let thread = std::thread::current();
        unsafe {
            signal_hook::register(*signal, move || {
                println!("{}", "server exit.");
                term_clone.store(true, Ordering::Release);
                thread.unpark();
            })
                .expect("failed to register signal handler");
        }
    }

    while !term.load(Ordering::Acquire) {
        std::thread::park();
    }
}