#![feature(async_await)]

pub mod wallet;
pub mod scripts;

#[cfg(test)]
mod wallet_test;

#[macro_use]
extern crate include_dir;
