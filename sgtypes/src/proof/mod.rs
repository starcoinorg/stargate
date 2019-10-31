// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use super::hash::ChannelTransactionAccumulatorHasher;
use libra_types::proof::AccumulatorProof;

pub type ChannelTransactionAccumulatorProof = AccumulatorProof<ChannelTransactionAccumulatorHasher>;

pub mod account_state_proof;
pub mod signed_channel_transaction_proof;
