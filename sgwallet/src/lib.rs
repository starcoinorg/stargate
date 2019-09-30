#![feature(async_await)]

pub mod scripts;
pub mod wallet;

#[cfg(test)]
mod wallet_test;

#[macro_use]
extern crate include_dir;
