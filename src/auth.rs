// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Storage
// SPDX-License-Identifier: Apache-2.0

//! Auth token verification for Buck.
//!
//! Re-exports the shared types from the sentin8-auth-client SDK and provides
//! thin wrappers matching the original Buck call sites (taking `&StorageConfig` + `&HeaderMap`).

use axum::http::{self, HeaderMap, StatusCode};

use crate::config::StorageConfig;

pub use sentin8::auth::client::AuthContext;

/// Verify the request identity — Bearer-first, certificate fallback
/// (DESIGN §5).
///
/// A Bearer JWT (user/delegated) is verified against the shared JWKS
/// client. When NO Authorization header is present, the TLS-injected
/// client-certificate workload identity resolves against the
/// boot-loaded registry map (auth DESIGN §4.3f — the certificate IS the
/// authentication, the map IS the authorization record): the
/// `func-storage` edge (func's WASM-binary PUT) presents its certificate
/// over the mTLS transport and carries no bearer.
///
/// # Errors
/// Returns the rejection (status + message) for a missing/invalid
/// bearer, or an unenrolled/disabled certificate workload.
pub async fn verify(
    state: &crate::handlers::AppState,
    headers: &HeaderMap,
) -> Result<AuthContext, (StatusCode, String)> {
    let has_bearer =
        headers.contains_key(http::header::AUTHORIZATION) || headers.contains_key("authorization");
    if !has_bearer {
        if let Some(workload) =
            sentin8::auth::client::resolve_workload_identity(&state.workload_registry, headers)
                .await?
        {
            let tls = sentin8::middleware::context::TLSContext::from_headers(headers);
            return Ok(AuthContext::from_workload(workload, tls.env_id));
        }
    }
    sentin8::auth::client::verify_bearer_token(&state.config.auth_client, headers).await
}

/// Verify the Bearer token and return the auth context.
pub async fn verify_token(
    config: &StorageConfig,
    headers: &HeaderMap,
) -> Result<AuthContext, (StatusCode, String)> {
    sentin8::auth::client::verify_bearer_token(&config.auth_client, headers).await
}

/// Extract the raw bearer token (compact JWT) from the Authorization
/// header, without verifying. Used for the bus-inbox publisher columns
/// (`publisher_id_token`) — the row already went through `verify_token`,
/// so this is audit context, not an authorization decision.
pub fn raw_bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .or_else(|| headers.get("authorization"))
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(|s| s.trim().to_string())
}
