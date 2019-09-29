#![feature(async_await)]

mod star_node;
mod mock_star_node;

#[cfg(test)]
mod chain_test;

pub mod star_chain_client;
pub mod client_state_view;

pub use star_node::setup_environment;
