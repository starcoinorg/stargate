//! This module defines error types used by sgstorage.

use failure::Fail;

/// This enum defines errors commonly used among SgStorage APIs.
#[derive(Debug, Fail)]
pub enum SgStorageError {
    /// A requested item is not found.
    #[fail(display = "{} not found.", _0)]
    NotFound(String),
    /// Requested too many items.
    #[fail(display = "Too many items requested: {}, max is {}", _0, _1)]
    TooManyRequested(u64, u64),
}
