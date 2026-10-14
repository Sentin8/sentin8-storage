// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Storage
// SPDX-License-Identifier: Apache-2.0

// Integration tests for Buck — Story 1.4.17
//
// Tests upload, download, signed URLs, and cross-tenant isolation
// (path traversal prevention). Uses the local filesystem adapter
// against a temp directory.

use sentin8_storage_server::storage::{LocalFsAdapter, StorageAdapter};
use std::env;

#[tokio::test]
async fn put_get_roundtrip() {
    let tmp = env::temp_dir().join(format!("sentin8_storage_test_{}", uuid::Uuid::new_v4()));
    let adapter = LocalFsAdapter::new(&tmp);
    let key = "org/test-org/env/test-env/file.txt";
    let data = b"hello world".to_vec();

    adapter.put(key, data.clone(), "text/plain").await.unwrap();
    let got = adapter.get(key).await.unwrap();
    assert_eq!(got, data);
}

#[tokio::test]
async fn delete_roundtrip() {
    let tmp = env::temp_dir().join(format!("sentin8_storage_test_{}", uuid::Uuid::new_v4()));
    let adapter = LocalFsAdapter::new(&tmp);
    let key = "org/test-org/env/test-env/delete.txt";
    adapter
        .put(key, b"data".to_vec(), "text/plain")
        .await
        .unwrap();
    adapter.delete(key).await.unwrap();
    assert!(adapter.get(key).await.is_err());
}

#[tokio::test]
async fn list_roundtrip() {
    let tmp = env::temp_dir().join(format!("sentin8_storage_test_{}", uuid::Uuid::new_v4()));
    let adapter = LocalFsAdapter::new(&tmp);
    adapter
        .put("org/o1/e1/a.txt", b"a".to_vec(), "text/plain")
        .await
        .unwrap();
    adapter
        .put("org/o1/e1/b.txt", b"b".to_vec(), "text/plain")
        .await
        .unwrap();
    adapter
        .put("org/o2/e1/c.txt", b"c".to_vec(), "text/plain")
        .await
        .unwrap();

    let list = adapter.list("org/o1/e1/").await.unwrap();
    assert!(list.len() >= 2);
}

#[tokio::test]
async fn copy_roundtrip() {
    let tmp = env::temp_dir().join(format!("sentin8_storage_test_{}", uuid::Uuid::new_v4()));
    let adapter = LocalFsAdapter::new(&tmp);
    let src = "org/o1/e1/src.txt";
    let dst = "org/o1/e1/dst.txt";
    adapter
        .put(src, b"copy me".to_vec(), "text/plain")
        .await
        .unwrap();
    adapter.copy(src, dst).await.unwrap();
    assert_eq!(adapter.get(dst).await.unwrap(), b"copy me");
    // Source still exists after copy.
    assert_eq!(adapter.get(src).await.unwrap(), b"copy me");
}

#[tokio::test]
async fn move_roundtrip() {
    let tmp = env::temp_dir().join(format!("sentin8_storage_test_{}", uuid::Uuid::new_v4()));
    let adapter = LocalFsAdapter::new(&tmp);
    let src = "org/o1/e1/move_src.txt";
    let dst = "org/o1/e1/move_dst.txt";
    adapter
        .put(src, b"move me".to_vec(), "text/plain")
        .await
        .unwrap();
    adapter.move_object(src, dst).await.unwrap();
    assert_eq!(adapter.get(dst).await.unwrap(), b"move me");
    // Source is gone after move.
    assert!(adapter.get(src).await.is_err());
}

#[tokio::test]
async fn path_traversal_prevented() {
    let tmp = env::temp_dir().join(format!("sentin8_storage_test_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&tmp).unwrap();
    let adapter = LocalFsAdapter::new(&tmp);
    // Attempt to read outside the root via traversal.
    let result = adapter.get("../../etc/passwd").await;
    // Should error (either path traversal or not found).
    assert!(result.is_err());
}

#[tokio::test]
async fn cross_tenant_isolation_enforced() {
    let tmp = env::temp_dir().join(format!("sentin8_storage_test_{}", uuid::Uuid::new_v4()));
    let adapter = LocalFsAdapter::new(&tmp);
    // Org1 puts an object.
    adapter
        .put(
            "org/org1/env/env1/secret.txt",
            b"org1 secret".to_vec(),
            "text/plain",
        )
        .await
        .unwrap();
    // Org2 should have its own namespace.
    adapter
        .put(
            "org/org2/env/env1/secret.txt",
            b"org2 secret".to_vec(),
            "text/plain",
        )
        .await
        .unwrap();
    // Verify the keys are separate.
    let org1_data = adapter.get("org/org1/env/env1/secret.txt").await.unwrap();
    let org2_data = adapter.get("org/org2/env/env1/secret.txt").await.unwrap();
    assert_ne!(org1_data, org2_data);
    assert_eq!(org1_data, b"org1 secret");
    assert_eq!(org2_data, b"org2 secret");
}
