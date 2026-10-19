// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Storage
// SPDX-License-Identifier: Apache-2.0

//! # storage-contracts
//!
//! Rust types for the Storage object-storage HTTP API - object metadata,
//! list pagination, and signed-URL responses.

#![deny(missing_docs)]

use serde::{Deserialize, Serialize};

/// Metadata for a stored object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObjectInfo {
    /// Object path within the environment namespace.
    pub path: String,
    /// Object size in bytes.
    pub size_bytes: i64,
    /// MIME content type.
    pub content_type: String,
    /// Integrity checksum (e.g. `sha256:…`), when computed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
    /// Creation timestamp (UTC).
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Last modification (UTC).
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Response from `GET .../objects?prefix=`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ListObjectsResponse {
    /// The listed objects.
    pub objects: Vec<ObjectInfo>,
    /// Continuation cursor for the next page (absent = end of listing).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Response from `POST .../sign-read`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedUrlResponse {
    /// The pre-signed URL.
    pub url: String,
    /// When the signature expires (UTC).
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn utc(s: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(s)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    #[test]
    fn object_info_roundtrip() {
        let o = ObjectInfo {
            path: "org/1/env/2/statements/2026-01.pdf".into(),
            size_bytes: 2048,
            content_type: "application/pdf".into(),
            checksum: Some("sha256:abcd".into()),
            created_at: utc("2026-01-01T00:00:00Z"),
            updated_at: utc("2026-01-01T00:00:00Z"),
        };
        let v = serde_json::to_value(&o).unwrap();
        assert_eq!(v["path"], "org/1/env/2/statements/2026-01.pdf");
        assert_eq!(v["size_bytes"], 2048);
        let back: ObjectInfo = serde_json::from_value(v).unwrap();
        assert_eq!(back, o);
    }

    #[test]
    fn object_info_checksum_omitted_when_none() {
        let o = ObjectInfo {
            path: "p".into(),
            size_bytes: 1,
            content_type: "text/plain".into(),
            checksum: None,
            created_at: utc("2026-01-01T00:00:00Z"),
            updated_at: utc("2026-01-01T00:00:00Z"),
        };
        let v = serde_json::to_value(&o).unwrap();
        assert!(v.get("checksum").is_none());
        let back: ObjectInfo = serde_json::from_value(v).unwrap();
        assert!(back.checksum.is_none());
    }

    #[test]
    fn list_objects_pagination_roundtrip() {
        let r = ListObjectsResponse {
            objects: vec![ObjectInfo {
                path: "a".into(),
                size_bytes: 1,
                content_type: "text/plain".into(),
                checksum: None,
                created_at: utc("2026-01-01T00:00:00Z"),
                updated_at: utc("2026-01-01T00:00:00Z"),
            }],
            next_cursor: Some("cursor-2".into()),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["next_cursor"], "cursor-2");
        let back: ListObjectsResponse = serde_json::from_value(v).unwrap();
        assert_eq!(back.objects.len(), 1);

        let empty: ListObjectsResponse = serde_json::from_value(json!({"objects": []})).unwrap();
        assert!(empty.objects.is_empty());
        assert!(empty.next_cursor.is_none());
    }

    #[test]
    fn signed_url_response_roundtrip() {
        let s = SignedUrlResponse {
            url: "https://storage.ops.sys.example.com/v1/storage/objects/x?sig=abc".into(),
            expires_at: utc("2026-01-01T01:00:00Z"),
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["expires_at"], "2026-01-01T01:00:00Z");
        let back: SignedUrlResponse = serde_json::from_value(v).unwrap();
        assert_eq!(back.url, s.url);
        assert_eq!(back.expires_at, s.expires_at);
    }
}
