// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Storage
// SPDX-License-Identifier: Apache-2.0

//! Storage configuration loaded from environment variables.

use std::env;

use sentin8::auth::client::{Client as AuthClient, ClientOptions};

#[derive(Debug, Clone)]
/// Configuration for storage.
pub struct StorageConfig {
    /// The port.
    pub port: u16,
    /// The storage adapter.
    pub storage_adapter: String,
    /// The local root.
    pub local_root: String,
    /// Auth JWKS URL for token verification.
    /// The sentin8 auth JWKS URL.
    pub sentin8_auth_jwks_url: String,
    /// Auth issuer for token verification.
    /// The sentin8 auth issuer.
    pub sentin8_auth_issuer: String,
    /// Shared Auth client — constructed once so the discovery and JWKS
    /// caches are reused across every request (5-minute TTL each).
    /// Cloning is cheap (the caches live behind an `Arc`).
    /// The auth client.
    pub auth_client: AuthClient,
    /// Database URL for the outbox table.
    /// The database URL.
    pub database_url: String,
    /// Bus base URL for event publication.
    /// The sentin8 bus URL.
    pub sentin8_bus_url: String,
    /// Bus stream family for Storage events (default `"storage"`).
    /// The stream family.
    pub stream_family: String,
    /// HMAC signing key for signed URL tokens. Random
    /// per-boot when unset — signed URLs are then only valid within the
    /// same process lifetime (single-node dev); production sets a stable key.
    /// The signing key.
    pub signing_key: Vec<u8>,
}

/// System Organization ID — used as fallback when token has no org claim.
/// The system org id constant.
pub const SYSTEM_ORG_ID: uuid::Uuid = uuid::Uuid::from_u128(0x00000000_0000_0000_0000_000000000001);
/// System Environment ID — used as fallback when token has no env claim.
/// The system env id constant.
pub const SYSTEM_ENV_ID: uuid::Uuid = uuid::Uuid::from_u128(0x00000000_0000_0000_0000_000000000002);

impl StorageConfig {
    /// Handle from env.
    pub fn from_env() -> Self {
        let cfg = sentin8::config::Sentin8Config::from_env();
        Self {
            port: env::var("SENTIN8_STORAGE_PORT")
                .expect("SENTIN8_STORAGE_PORT must be set by captain")
                .parse()
                .expect("SENTIN8_STORAGE_PORT must be a valid u16"),
            storage_adapter: env::var("SENTIN8_STORAGE_STORAGE_ADAPTER").unwrap_or("local".into()),
            local_root: env::var("SENTIN8_STORAGE_LOCAL_ROOT")
                .unwrap_or_else(|_| sentin8::config::storage_dir()),
            sentin8_auth_jwks_url: env::var("SENTIN8_AUTH_JWKS_URL")
                .unwrap_or_else(|_| cfg.sentin8_auth_jwks_url()),
            sentin8_auth_issuer: env::var("SENTIN8_AUTH_ISSUER")
                .unwrap_or_else(|_| cfg.sentin8_auth_issuer()),
            auth_client: AuthClient::new(ClientOptions {
                base_url: env::var("SENTIN8_AUTH_ISSUER")
                    .unwrap_or_else(|_| cfg.sentin8_auth_issuer()),
                ..Default::default()
            }),
            database_url: env::var("SENTIN8_STORAGE_DATABASE_URL").unwrap_or_else(|_| {
                env::var("DATABASE_URL").unwrap_or_else(|_| {
                    sentin8::config::Sentin8Config::default_database_url().to_string()
                })
            }),
            sentin8_bus_url: env::var("SENTIN8_BUS_URL").unwrap_or_else(|_| cfg.sentin8_bus_url()),
            stream_family: env::var("SENTIN8_STORAGE_STREAM_FAMILY")
                .unwrap_or_else(|_| "storage".into()),
            signing_key: match env::var("SENTIN8_STORAGE_SIGNING_KEY") {
                Ok(k) if !k.is_empty() => k.into_bytes(),
                _ => {
                    // Fail-fast in production (storage DESIGN §5): a restart
                    // would invalidate every signed URL. Dev mode keeps the
                    // ephemeral fallback with the loud warning.
                    let production = matches!(
                        env::var("SENTIN8_ENV").as_deref(),
                        Ok("production") | Ok("prod")
                    );
                    if production {
                        panic!(
                            "SENTIN8_STORAGE_SIGNING_KEY must be set in production — ephemeral keys invalidate signed URLs on restart"
                        );
                    }
                    let k: [u8; 32] = rand::random();
                    tracing::info!(
                        "SENTIN8_STORAGE_SIGNING_KEY not set — generated ephemeral signing key (signed URLs reset on restart)"
                    );
                    k.to_vec()
                }
            },
        }
    }
}
