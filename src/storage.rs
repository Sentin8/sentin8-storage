// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Storage
// SPDX-License-Identifier: Apache-2.0

//! Storage adapter interface and local filesystem implementation.
//!
//! Adapters implement: `Put`, `Get`, `Delete`, `List`, `SignedReadURL`,
//! `SignedUploadURL`, `Copy`, `Move`.

use std::path::{Component, Path, PathBuf};
use tokio::fs;

#[derive(Debug, thiserror::Error)]
/// Errors returned by storage.
pub enum StorageError {
    /// The object does not exist.
    #[error("object not found: {0}")]
    NotFound(String),
    /// The key escapes its bucket root (rejected before any IO).
    #[error("path traversal detected: {0}")]
    PathTraversal(String),
    /// An underlying IO failure.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

// ── Signed URL tokens ────────────────────────────────────

/// The HTTP method a signed URL token authorizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The signedmethod type.
pub enum SignedMethod {
    /// The get variant.
    Get,
    /// The put variant.
    Put,
}

impl SignedMethod {
    /// Handle as str.
    pub fn as_str(&self) -> &'static str {
        match self {
            SignedMethod::Get => "GET",
            SignedMethod::Put => "PUT",
        }
    }
}

/// HMAC-SHA256-signed URL token codec.
///
/// Token format: `base64url(payload) || "." || base64url(hmac)` where
/// `payload = "{key}|{expiry_epoch}|{METHOD}"`. The signature covers the
/// full payload - the key, the expiry and the method are all tamper-proof.
/// The signedurlcodec type.
pub struct SignedUrlCodec {
    key: Vec<u8>,
}

impl SignedUrlCodec {
    /// Handle new.
    pub fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }

    fn sign(&self, payload: &str) -> String {
        use base64::Engine;
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(&self.key).expect("HMAC accepts any key length");
        mac.update(payload.as_bytes());
        let out = mac.finalize().into_bytes();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(out)
    }

    /// Issue a signed-URL token for `key` valid for `ttl_secs`.
    /// Issue it.
    pub fn issue(&self, key: &str, ttl_secs: i64, method: SignedMethod) -> String {
        use base64::Engine;
        let expiry = chrono::Utc::now().timestamp() + ttl_secs;
        let payload = format!("{key}|{expiry}|{}", method.as_str());
        let sig = self.sign(&payload);
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
        format!("{payload_b64}.{sig}")
    }

    /// Verify a token. Returns the object key and authorized method, or an
    /// error string describing the failure (invalid / expired / forged).
    /// Verify it.
    pub fn verify(&self, token: &str) -> Result<(String, SignedMethod), String> {
        use base64::Engine;
        let (payload_b64, sig) = token.rsplit_once('.').ok_or("invalid token format")?;
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| "invalid token encoding")?;
        let payload = String::from_utf8(payload).map_err(|_| "invalid token encoding")?;
        let expected = self.sign(&payload);
        if sig != expected {
            return Err("token signature mismatch".into());
        }
        let parts: Vec<&str> = payload.splitn(3, '|').collect();
        if parts.len() != 3 {
            return Err("invalid token format".into());
        }
        let key = parts[0].to_string();
        let expiry: i64 = parts[1].parse().map_err(|_| "invalid token expiry")?;
        if chrono::Utc::now().timestamp() > expiry {
            return Err("signed URL expired".into());
        }
        let method = match parts[2] {
            "GET" => SignedMethod::Get,
            "PUT" => SignedMethod::Put,
            other => return Err(format!("unknown token method {other}")),
        };
        Ok((key, method))
    }
}

/// The storage adapter trait. All methods are async.
#[async_trait::async_trait]
pub trait StorageAdapter: Send + Sync {
    /// Write an object.
    async fn put(&self, key: &str, data: Vec<u8>, content_type: &str) -> Result<(), StorageError>;
    /// Read an object.
    async fn get(&self, key: &str) -> Result<Vec<u8>, StorageError>;
    /// Delete an object.
    async fn delete(&self, key: &str) -> Result<(), StorageError>;
    /// List object keys under a prefix.
    async fn list(&self, prefix: &str) -> Result<Vec<String>, StorageError>;
    /// Existence probe without reading the payload (the dedup fast
    /// path - Storage design `HEAD /objects/{path}`).
    async fn exists(&self, key: &str) -> Result<bool, StorageError> {
        // Default: a 0-byte read attempt; adapters with native HEAD
        // (S3-style) override.
        match self.get(key).await {
            Ok(_) => Ok(true),
            Err(StorageError::NotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }
    /// Object size in bytes (HEAD response field; NotFound when the
    /// object is absent).
    async fn size(&self, key: &str) -> Result<u64, StorageError> {
        self.get(key).await.map(|d| d.len() as u64)
    }
    /// Copy an object from `src` to `dst`
    async fn copy(&self, src: &str, dst: &str) -> Result<(), StorageError> {
        let data = self.get(src).await?;
        self.put(dst, data, "application/octet-stream").await
    }
    /// Move an object from `src` to `dst`
    async fn move_object(&self, src: &str, dst: &str) -> Result<(), StorageError> {
        self.copy(src, dst).await?;
        self.delete(src).await
    }
}

/// Local filesystem adapter. Stores objects under `root/{key}`.
/// The localfsadapter type.
pub struct LocalFsAdapter {
    root: PathBuf,
}

impl LocalFsAdapter {
    /// Handle new.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        // Canonicalize the root once at construction so `safe_path` can
        // compare an absolute canonical root against the canonicalized
        // object path. Falls back to the raw root if it doesn't exist yet
        // (e.g. fresh install before the first object is written).
        let canonical_root = root.canonicalize().unwrap_or(root);
        Self {
            root: canonical_root,
        }
    }

    fn safe_path(&self, key: &str) -> Result<PathBuf, StorageError> {
        // Reject traversal at the component level BEFORE any filesystem
        // access: a key like `a/../../x` must never resolve outside the
        // root. The old canonicalize-then-compare approach was bypassable
        // on write paths (the target file does not exist yet, so
        // canonicalize fell back to the raw, non-normalized path, which
        // still `starts_with` the root component-wise).
        let path = self.root.join(key);
        let mut comps = path.components();
        comps.next(); // skip the root prefix
        if comps.clone().any(|c| matches!(c, Component::ParentDir)) {
            return Err(StorageError::PathTraversal(key.into()));
        }
        // Canonicalize the deepest EXISTING directory and re-append the
        // non-existent tail, then re-verify containment - this catches
        // symlink escapes without requiring the target file to exist.
        let (existing, tail) = self.split_existing(&path);
        let canonical_base = existing
            .canonicalize()
            .map_err(|_| StorageError::PathTraversal(key.into()))?;
        let resolved = tail.iter().fold(canonical_base, |p, seg| p.join(seg));
        if !resolved.starts_with(&self.root) {
            return Err(StorageError::PathTraversal(key.into()));
        }
        Ok(path)
    }

    /// Split `path` into its deepest existing ancestor and the remaining
    /// non-existent tail segments (in order).
    fn split_existing(&self, path: &Path) -> (PathBuf, Vec<std::ffi::OsString>) {
        let mut segments: Vec<std::ffi::OsString> = Vec::new();
        let mut cur = path.to_path_buf();
        loop {
            if cur.exists() || cur.parent().is_none() {
                break;
            }
            match cur.file_name() {
                Some(name) => segments.push(name.to_os_string()),
                None => break,
            }
            cur = cur.parent().map(|p| p.to_path_buf()).unwrap_or(cur);
        }
        segments.reverse();
        (cur, segments)
    }
}

#[async_trait::async_trait]
impl StorageAdapter for LocalFsAdapter {
    async fn put(&self, key: &str, data: Vec<u8>, _content_type: &str) -> Result<(), StorageError> {
        let path = self.safe_path(key)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::write(&path, data).await?;
        Ok(())
    }

    /// Read an object.
    async fn get(&self, key: &str) -> Result<Vec<u8>, StorageError> {
        let path = self.safe_path(key)?;
        match fs::read(&path).await {
            Ok(data) => Ok(data),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(StorageError::NotFound(key.into()))
            }
            Err(e) => Err(StorageError::Io(e)),
        }
    }

    /// Native HEAD - metadata only, no payload read.
    async fn exists(&self, key: &str) -> Result<bool, StorageError> {
        let path = self.safe_path(key)?;
        match fs::metadata(&path).await {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(StorageError::Io(e)),
        }
    }

    /// Native size - metadata only, no payload read.
    async fn size(&self, key: &str) -> Result<u64, StorageError> {
        let path = self.safe_path(key)?;
        match fs::metadata(&path).await {
            Ok(m) => Ok(m.len()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(StorageError::NotFound(key.into()))
            }
            Err(e) => Err(StorageError::Io(e)),
        }
    }

    /// Delete an object.
    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        let path = self.safe_path(key)?;
        match fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(StorageError::NotFound(key.into()))
            }
            Err(e) => Err(StorageError::Io(e)),
        }
    }

    /// List object keys under a prefix.
    async fn list(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
        let base = self.root.join(prefix);
        if !base.exists() {
            return Ok(vec![]);
        }
        let mut entries = vec![];
        let mut stack = vec![base.clone()];
        while let Some(dir) = stack.pop() {
            let mut rd = fs::read_dir(&dir).await?;
            while let Some(entry) = rd.next_entry().await? {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if let Ok(rel) = path.strip_prefix(&self.root) {
                    entries.push(rel.to_string_lossy().to_string());
                }
            }
        }
        Ok(entries)
    }
}

#[cfg(test)]
mod signed_codec_tests {
    use super::*;

    #[test]
    fn roundtrip_get() {
        let codec = SignedUrlCodec::new(b"test-key");
        let tok = codec.issue("org/o/env/e/a.txt", 60, SignedMethod::Get);
        let (key, m) = codec.verify(&tok).unwrap();
        assert_eq!(key, "org/o/env/e/a.txt");
        assert_eq!(m, SignedMethod::Get);
    }

    #[test]
    fn forged_token_rejected() {
        let codec = SignedUrlCodec::new(b"test-key");
        let tok = codec.issue("org/o/env/e/a.txt", 60, SignedMethod::Get);
        // Tamper with the payload (flip a char).
        let tampered = format!("{}X.{}", &tok[..tok.find('.').unwrap()], {
            let (_, s) = tok.rsplit_once('.').unwrap();
            s.to_string()
        });
        assert!(codec.verify(&tampered).is_err());
        // Re-sign with a different key.
        let codec2 = SignedUrlCodec::new(b"other-key");
        assert!(codec2.verify(&tok).is_err());
    }

    #[test]
    fn expired_token_rejected() {
        let codec = SignedUrlCodec::new(b"test-key");
        let tok = codec.issue("k", -1, SignedMethod::Get);
        assert!(codec.verify(&tok).is_err());
    }

    #[test]
    fn method_is_carried() {
        let codec = SignedUrlCodec::new(b"test-key");
        let tok = codec.issue("k", 60, SignedMethod::Put);
        let (_, m) = codec.verify(&tok).unwrap();
        assert_eq!(m, SignedMethod::Put);
    }
}
