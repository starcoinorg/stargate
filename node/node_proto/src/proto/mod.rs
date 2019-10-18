// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use ::libra_types::proto::*;
use ::sgtypes::proto::*;

pub mod node {
    include!(concat!(env!("OUT_DIR"), "/node.rs"));
}
