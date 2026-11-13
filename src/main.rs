// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Storage
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 Storage - object/file storage with pluggable adapters.
//!
//! See.
//!
//! Boot runs on the platform `sentin8-shell` crate (design
//! ): registration
//! flag, PQ provider, config, capped pool, PG18 check, state binding, OpenAPI
//! merge, middleware stack and PQ-TLS listener are owned by the shell. This
//! binary supplies only its registration data, state and routes.

#[allow(dead_code)]
mod admin_ui;
#[allow(dead_code)]
mod auth;
#[allow(dead_code)]
mod config;
#[allow(dead_code)]
mod handlers;
mod openapi;

// The utoipa dump as a fn pointer for registration.rs (which cannot
// name crate::openapi - embedded test harnesses have no openapi module;
// see registration.rs and the mirrored static in lib.rs).
#[cfg_attr(test, allow(dead_code))]
static OPENAPI_DUMP: fn() -> serde_json::Value = || {
    use utoipa::OpenApi as _;
    serde_json::to_value(openapi::StorageOpenApi::openapi()).unwrap_or(serde_json::Value::Null)
};

mod policy;
mod registration;
#[allow(dead_code)]
mod server;
#[allow(dead_code)]
mod storage;

use utoipa::OpenApi;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sentin8::shell::serve(
        sentin8::shell::Sentin8Shell::new("sentin8:storage", "SENTIN8_STORAGE")
            .with_registration(registration::print)
            .with_state(server::build_state)
            .with_own_health()
            .with_router(|router, _state| server::routes(router))
            .with_openapi(openapi::StorageOpenApi::openapi()),
    )
    .await
}
