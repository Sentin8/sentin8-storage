// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Storage
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 Storage - library re-exports for integration tests.

#![deny(missing_docs)]

/// Admin UI (RFW) handlers.
pub mod admin_ui;
/// Produce/consume authentication helpers.
pub mod auth;
/// Environment configuration.
pub mod config;
/// HTTP handlers - object CRUD, buckets, signed URLs.
pub mod handlers;
/// OpenAPI spec assembly.
pub mod openapi;

// The utoipa dump for registration::print - mirrored from main.rs; the
// lib crate compiles registration::print too (test harnesses embedding
// via #[path] never invoke it, so the pointer is referenced, not run).
#[cfg_attr(test, allow(dead_code))]
static OPENAPI_DUMP: fn() -> serde_json::Value = || {
    use utoipa::OpenApi as _;
    serde_json::to_value(openapi::StorageOpenApi::openapi()).unwrap_or(serde_json::Value::Null)
};

/// Shield (Sentin8:Policy) integration - shared bridge re-exports.
pub mod policy;
/// Service self-registration declarations.
pub mod registration;
/// Axum router and server.
pub mod server;
/// Object storage primitives (write/read/delete, signed URLs, copy/move).
pub mod storage;
