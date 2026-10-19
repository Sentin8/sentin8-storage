//! sentin8-storage-sdk - per-service SDK mini-facade (SDD §3.1).
//!
//! Re-exports the service's client + contracts crates. No logic, no
//! features (SDD-4b). Consumers import as `use sentin8_storage_sdk::{client|contracts}::…`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// storage-client - HTTP client (re-export).
pub mod client {
    pub use sentin8_storage_client::*;
}

/// storage-contracts - wire types + OpenAPI spec (re-export).
pub mod contracts {
    pub use sentin8_storage_contracts::*;
}
