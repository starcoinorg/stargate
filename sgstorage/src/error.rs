// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! This module defines error types used by sgstorage.

use thiserror::Error;

/// This enum defines errors commonly used among SgStorage APIs.
#[derive(Debug, Error)]
pub enum SgStorageError {
    /// A requested item is not found.
    #[error("{0} not found.")]
    NotFound(String),
    /// Requested too many items.
    #[error("Too many items requested: {0}, max is {1}")]
    TooManyRequested(u64, u64),
}
