// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Storage
// SPDX-License-Identifier: Apache-2.0

//! # storage-client
//!
//! Rust HTTP client for the Storage object-storage service.
//!
//! Route shape: env-scoped objects live at the flat path
//! `/v1/storage/objects/{path}` - the tenant env is resolved server-side
//! from the bearer token, never from URL path segments. The physical key
//! layout `org/{org}/env/{env}/…` is server-internal. Org-scoped assets
//! ride the env route with an org-prefixed object path (there are no
//! org-namespace client methods).

#![deny(missing_docs)]

use sentin8_middleware::http_client::Sentin8HttpClient;
use sentin8_storage_contracts::ListObjectsResponse;
use thiserror::Error;

#[derive(Debug, Error)]
/// Failure surface for Storage client calls.
pub enum StorageError {
    /// An HTTP request failed (transport error or non-success status).
    #[error("Storage HTTP error: {0}")]
    Http(String),
    /// A response body could not be decoded.
    #[error("Storage response decode error: {0}")]
    Decode(String),
}

#[derive(Clone)]
/// HTTP client for the Storage object-storage service -
/// **certificate-presenting** (auth DESIGN §4.3f): every
/// call presents the workload's Acme-issued client certificate in the
/// TLS handshake; Storage's TLS layer authenticates it and the registry
/// map authorizes the scopes. No bearer token exists on this path.
pub struct StorageClient {
    /// Trimmed base URL of the Storage server.
    base_url: String,
    /// mTLS transport (presents the workload certificate on every call).
    http: Sentin8HttpClient,
}

impl StorageClient {
    /// Build a certificate-presenting StorageClient. The transport
    /// presents `cert_path`/`key_path` (the workload's Acme-issued
    /// identity) on every call and trusts only `ca_cert_path` - Storage's
    /// TLS layer CA-verifies the presented certificate and injects the
    /// `X-Sentin8-Client-Cert-*` headers that drive authorization.
    ///
    /// # Errors
    /// [`StorageError::Http`] when the mTLS transport cannot be built
    /// (missing files / unreadable key) - a missing certificate identity
    /// is a provisioning state, surfaced loud.
    pub fn with_workload_identity(
        base_url: impl Into<String>,
        ca_cert_path: &str,
        cert_path: &str,
        key_path: &str,
    ) -> Result<Self, StorageError> {
        let mtls = sentin8_middleware::mtls::MtlsConfig::new(ca_cert_path, cert_path, key_path);
        let http = sentin8_middleware::mtls::build_mtls_client(&mtls)
            .map(Sentin8HttpClient::from_client)
            .map_err(|e| StorageError::Http(e.to_string()))?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http,
        })
    }

    /// Test-only plain-HTTP constructor - talks to a local test server
    /// with no TLS/identity (the wire tests exercise paths and headers,
    /// not authentication; the mTLS transport is covered by the
    /// with_workload_identity build path).
    #[cfg(test)]
    fn plain(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http: Sentin8HttpClient::new(),
        }
    }

    /// Plain-HTTP DEV FALLBACK constructor - no TLS identity (Storage
    /// rejects it loudly at the authorization gate). Use ONLY for the
    /// fail-soft boot path when the workload certificate cannot be minted
    /// yet (Acme still coming up): the caller retries its boot identity
    /// on the next restart. Never for production paths.
    pub fn new_dev_plain(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http: Sentin8HttpClient::new(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// Upload bytes to the environment namespace.
    pub async fn put(
        &self,
        _org_id: &str,
        _env_id: &str,
        object_path: &str,
        content_type: &str,
        data: Vec<u8>,
    ) -> Result<(), StorageError> {
        // env_id is resolved server-side from the TLS-injected identity context.
        let url = self.url(&format!("/v1/storage/objects/{object_path}"));
        let resp = self
            .http
            .put(url)
            .header("Content-Type", content_type)
            .body(data)
            .send()
            .await
            .map_err(|e| StorageError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(StorageError::Http(format!("status {}", resp.status())));
        }
        Ok(())
    }

    /// Existence probe without reading the payload - the dedup fast
    /// path. Returns `Ok(None)` when the object does not exist.
    pub async fn head(
        &self,
        _org_id: &str,
        _env_id: &str,
        object_path: &str,
    ) -> Result<Option<u64>, StorageError> {
        let url = self.url(&format!("/v1/storage/objects/{object_path}"));
        let resp = self
            .http
            .head(url)
            .send()
            .await
            .map_err(|e| StorageError::Http(e.to_string()))?;
        match resp.status().as_u16() {
            200 => {
                let len = resp
                    .headers()
                    .get(reqwest::header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                Ok(Some(len))
            }
            404 => Ok(None),
            s => Err(StorageError::Http(format!("status {s}"))),
        }
    }

    /// Put-if-absent - the idempotent upload for content-addressed
    /// objects: skips the payload write when the object already exists.
    /// Returns `Ok(true)` when the bytes were written, `Ok(false)` when
    /// dedup short-circuited.
    pub async fn put_if_absent(
        &self,
        _org_id: &str,
        _env_id: &str,
        object_path: &str,
        content_type: &str,
        data: Vec<u8>,
    ) -> Result<bool, StorageError> {
        let url = self.url(&format!("/v1/storage/objects/{object_path}"));
        let resp = self
            .http
            .put(url)
            .header("Content-Type", content_type)
            .header("X-If-Absent", "true")
            .body(data)
            .send()
            .await
            .map_err(|e| StorageError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(StorageError::Http(format!("status {}", resp.status())));
        }
        // The server reports dedup hits via the marker header.
        let deduped = resp
            .headers()
            .get("X-Storage-Deduped")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        Ok(!deduped)
    }

    /// Download bytes from the environment namespace.
    pub async fn get(
        &self,
        _org_id: &str,
        _env_id: &str,
        object_path: &str,
    ) -> Result<Vec<u8>, StorageError> {
        // env_id is resolved server-side from the TLS-injected identity context.
        let url = self.url(&format!("/v1/storage/objects/{object_path}"));
        let resp = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| StorageError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(StorageError::Http(format!("status {}", resp.status())));
        }
        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| StorageError::Decode(e.to_string()))
    }

    /// List objects under a prefix.
    pub async fn list(
        &self,
        _org_id: &str,
        _env_id: &str,
        prefix: &str,
    ) -> Result<ListObjectsResponse, StorageError> {
        let url = self.url(&format!("/v1/storage/objects?prefix={prefix}"));
        let resp = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| StorageError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(StorageError::Http(format!("status {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| StorageError::Decode(e.to_string()))
    }

    /// Delete an object.
    pub async fn delete(
        &self,
        _org_id: &str,
        _env_id: &str,
        object_path: &str,
    ) -> Result<(), StorageError> {
        let url = self.url(&format!("/v1/storage/objects/{object_path}"));
        let resp = self
            .http
            .delete(url)
            .send()
            .await
            .map_err(|e| StorageError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(StorageError::Http(format!("status {}", resp.status())));
        }
        Ok(())
    }

    /// Generate a signed read URL (time-limited).
    pub async fn sign_read(
        &self,
        _org_id: &str,
        _env_id: &str,
        object_path: &str,
    ) -> Result<serde_json::Value, StorageError> {
        let url = self.url(&format!("/v1/storage/objects/{object_path}/sign-read"));
        let resp = self
            .http
            .post(url)
            .send()
            .await
            .map_err(|e| StorageError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(StorageError::Http(format!("status {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| StorageError::Decode(e.to_string()))
    }

    /// Generate a signed upload URL (time-limited).
    pub async fn sign_upload(
        &self,
        _org_id: &str,
        _env_id: &str,
        object_path: &str,
    ) -> Result<serde_json::Value, StorageError> {
        let url = self.url(&format!("/v1/storage/objects/{object_path}/sign-upload"));
        let resp = self
            .http
            .post(url)
            .send()
            .await
            .map_err(|e| StorageError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(StorageError::Http(format!("status {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| StorageError::Decode(e.to_string()))
    }

    /// `GET /v1/health` - health check.
    pub async fn health(&self) -> Result<serde_json::Value, StorageError> {
        let resp = self
            .http
            .get(self.url("/v1/health"))
            .send()
            .await
            .map_err(|e| StorageError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(StorageError::Http(format!("status {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| StorageError::Decode(e.to_string()))
    }
}

// Pure tests: route shapes (env-scoped flat paths), the put_if_absent
// dedup-header contract, and the head() existence-probe semantics.

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn install_provider() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = sentin8_tls::crypto::sentin8_pq_provider().install_default();
        });
    }

    /// One-shot HTTP server: reads a request, answers per `responder`, returns
    /// the raw request text.
    async fn serve<F>(responder: F) -> (tokio::task::JoinHandle<String>, std::net::SocketAddr)
    where
        F: FnOnce() -> String + Send + 'static,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let resp = responder();
            sock.write_all(resp.as_bytes()).await.unwrap();
            req
        });
        (handle, addr)
    }

    fn json_resp(status: u16, body: &str, extra_headers: &[(&str, &str)]) -> String {
        let mut s = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        );
        for (k, v) in extra_headers {
            s.push_str(&format!("{k}: {v}\r\n"));
        }
        s.push_str("Connection: close\r\n\r\n");
        s.push_str(body);
        s
    }

    #[tokio::test]
    async fn put_uses_flat_env_scoped_path_and_content_type() {
        install_provider();
        let (handle, addr) = serve(|| json_resp(200, "{}", &[])).await;
        let c = StorageClient::plain(format!("http://{addr}"));
        c.put(
            "org-ignored",
            "env-ignored",
            "statements/2026-01.pdf",
            "application/pdf",
            vec![1, 2, 3],
        )
        .await
        .unwrap();
        let raw = handle.await.unwrap();
        // Tenant env resolved server-side - path carries no org/env.
        assert!(
            raw.starts_with("PUT /v1/storage/objects/statements/2026-01.pdf HTTP/1.1"),
            "got: {raw}"
        );
        assert!(
            raw.contains("content-type: application/pdf")
                || raw.contains("Content-Type: application/pdf")
        );
        // no Authorization header exists on the platform path -
        // the identity rides the TLS handshake (absent in this plain-HTTP
        // test transport).
        assert!(
            !raw.contains("authorization:") && !raw.contains("Authorization:"),
            "no bearer header may be attached: {raw}"
        );
    }

    #[tokio::test]
    async fn head_404_maps_to_none() {
        install_provider();
        let (handle, addr) = serve(|| {
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
        })
        .await;
        let c = StorageClient::plain(format!("http://{addr}"));
        let out = c.head("o", "e", "missing.pdf").await.unwrap();
        assert_eq!(out, None, "404 must map to Ok(None) - dedup fast path");
        let raw = handle.await.unwrap();
        assert!(
            raw.starts_with("HEAD /v1/storage/objects/missing.pdf HTTP/1.1"),
            "got: {raw}"
        );
    }

    #[tokio::test]
    async fn put_if_absent_reports_dedup_header() {
        install_provider();
        // Server reports a dedup hit → client returns Ok(false).
        let (handle, addr) = serve(|| json_resp(200, "{}", &[("X-Storage-Deduped", "true")])).await;
        let c = StorageClient::plain(format!("http://{addr}"));
        let written = c
            .put_if_absent("o", "e", "ca/abc123", "application/octet-stream", vec![9])
            .await
            .unwrap();
        assert!(!written, "dedup hit must report not-written");
        let raw = handle.await.unwrap();
        assert!(raw.contains("x-if-absent: true") || raw.contains("X-If-Absent: true"));

        // Fresh object → written=true.
        let (handle2, addr2) = serve(|| json_resp(200, "{}", &[])).await;
        let c2 = StorageClient::plain(format!("http://{addr2}"));
        let written2 = c2
            .put_if_absent("o", "e", "ca/def456", "application/octet-stream", vec![9])
            .await
            .unwrap();
        assert!(written2);
        handle2.await.unwrap();
    }

    #[tokio::test]
    async fn org_scoped_assets_use_env_route_with_object_prefix() {
        // Org-scoped assets are stored under the env route with an
        // org-prefixed object path.
        install_provider();
        let (handle, addr) = serve(|| json_resp(200, "{}", &[])).await;
        let c = StorageClient::plain(format!("http://{addr}"));
        c.put(
            "org-ignored",
            "env-ignored",
            "org-77/branding/logo.png",
            "image/png",
            vec![1],
        )
        .await
        .unwrap();
        let raw = handle.await.unwrap();
        assert!(
            raw.starts_with("PUT /v1/storage/objects/org-77/branding/logo.png HTTP/1.1"),
            "got: {raw}"
        );
    }

    #[tokio::test]
    async fn sign_read_is_post_with_json_body() {
        install_provider();
        let (handle, addr) = serve(|| {
            json_resp(
                200,
                r#"{"url":"https://storage/x?sig=a","expires_at":"2026-01-01T01:00:00Z"}"#,
                &[],
            )
        })
        .await;
        let c = StorageClient::plain(format!("http://{addr}"));
        let out = c.sign_read("o", "e", "statements/s.pdf").await.unwrap();
        assert!(out["url"].as_str().unwrap().contains("sig="));
        let raw = handle.await.unwrap();
        assert!(
            raw.starts_with("POST /v1/storage/objects/statements/s.pdf/sign-read HTTP/1.1"),
            "got: {raw}"
        );
    }

    #[tokio::test]
    async fn error_status_maps_to_storage_error() {
        install_provider();
        let (handle, addr) = serve(|| json_resp(403, "{}", &[])).await;
        let c = StorageClient::plain(format!("http://{addr}"));
        let err = c.get("o", "e", "denied.pdf").await.unwrap_err();
        assert!(
            matches!(err, StorageError::Http(ref m) if m.contains("403")),
            "{err:?}"
        );
        handle.await.unwrap();
    }
}
