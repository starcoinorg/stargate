// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use super::hash::WriteSetItemHasher;
use super::impl_hash;
use libra_types::access_path::AccessPath;
use libra_types::write_set::WriteOp;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WriteSetItem(pub AccessPath, pub WriteOp);

impl_hash!(WriteSetItem, WriteSetItemHasher);
