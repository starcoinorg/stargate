#![feature(async_await)]

mod mock_star_node;
mod star_node;

#[cfg(test)]
mod chain_test;

pub mod client_state_view;
pub mod star_chain_client;

pub use star_node::setup_environment;
