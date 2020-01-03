//! Implementation of libp2p's `NetworkBehaviour` trait that opens a single substream with the
//! remote and then allows any communication with them.
//!
//! The `Protocol` struct uses `LegacyProto` in order to open substreams with the rest of the
//! network, then performs the Substrate protocol handling on top.

pub use behaviour::{LegacyProto, LegacyProtoOut};
mod behaviour;
mod handler;
mod tests;
mod upgrade;
