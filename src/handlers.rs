// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Storage
// SPDX-License-Identifier: Apache-2.0

//! HTTP handlers for Storage's object storage API.
//!
//! All tenant context is resolved from TLS-injected headers via the auth
//! token's `env_id` claim (globally unique). `org_id` is resolved internally
//! from `env_id` via `sys.environments` for the storage key prefix
//! (`org/{org_id}/env/{env_id}/...`) - it never appears in URL paths.

use axum::Json;
use sentin8::middleware::health::LiveHealth;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use utoipa::ToSchema;

use crate::config::StorageConfig;
use crate::storage::{SignedMethod, SignedUrlCodec, StorageAdapter, StorageError};

#[derive(Clone)]
/// app state.
pub struct AppState {
    /// The config.
    pub config: Arc<StorageConfig>,
    /// The adapter.
    pub adapter: Arc<dyn StorageAdapter>,
    /// DB connection pool for the outbox table + org_id resolution.
    /// The pool.
    pub pool: sqlx::PgPool,
    /// HMAC codec for signed URL tokens.
    /// The signed codec.
    pub signed_codec: Arc<SignedUrlCodec>,
    /// Shield engine ( - ): additional gate after scope.
    /// The policy.
    pub policy: Arc<crate::policy::Engine>,
    /// Shared Sentin8:Policy admin surface ( - one
    /// implementation for every service; mounted in server::routes).
    /// The admin.
    pub admin: sentin8::shield::admin::SharedAdminState,
    /// Boot-loaded platform workload registry map (auth DESIGN §4.3f) -
    /// the authorization record for certificate-presenting M2M calls
    /// (the `func-storage` WASM upload edge; no bearer exists there).
    /// The workload registry.
    pub workload_registry: sentin8::auth::workload_registry::WorkloadMap,
}

/// Handle health.
#[utoipa::path(
    get,
    path = "/v1/health",
    responses(
        (status = 200, description = "Liveness (version, build, disk usage)", body = sentin8::middleware::health::LiveHealth),
    ),
    security(),
    tag = "meta",
)]
pub async fn health() -> Json<LiveHealth> {
    Json(LiveHealth {
        status: "ok".to_string(),
        service: None,
        version: Some(sentin8::build_info::id()),
        build: Some(sentin8::build_info::build_hash().to_string()),
        active_connections: sentin8::middleware::traffic_counter::process_active_connections()
            .map(|n| n as i64),
    })
}

/// Resolve `org_id` from `env_id` via `sys.environments`. Fails closed:
/// a DB error or an unknown env is an error - the caller must never fall
/// back to a default org ( authorization pipeline: reject, never default).
/// Schema-qualified: the service role's search_path is `storage, public`
/// (DBX ) - unqualified cross-schema names fail at runtime.
/// Same-connection tenant context : the `sys_environments_select`
/// RLS policy gates on `sentin8_context_initialized`, so the context is
/// set on the SAME pooled connection the lookup runs on - a bare-pool
/// SELECT silently returns 0 rows (FORCE RLS) and surfaced as a spurious
/// 404 "environment not found" instead of a real answer.
async fn resolve_org_id(
    pool: &sqlx::PgPool,
    env_id: uuid::Uuid,
) -> Result<uuid::Uuid, (StatusCode, String)> {
    // The context is transaction-local (`set_config(..., true)`) and sqlx
    // runs each pooled statement in its OWN implicit transaction - the
    // context-set and the lookup must share ONE explicit transaction or the
    // context evaporates before the query runs ( rule 2; mirrors BFF
    // `resolve_org_id_from_env_id`).
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("pool: {e}")))?;
    let _ = sqlx::query(
        "SELECT sentin8_set_tenant_context($1, NULL, NULL, NULL, false, false, false, NULL, NULL)",
    )
    .bind(env_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("context: {e}")))?;
    let org_id =
        sqlx::query_scalar::<_, uuid::Uuid>("SELECT org_id FROM sys.environments WHERE id = $1")
            .bind(env_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}")))?
            .ok_or((StatusCode::NOT_FOUND, "environment not found".into()))?;
    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("commit: {e}")))?;
    Ok(org_id)
}

/// Build the storage key prefix: `org/{org_id}/env/{env_id}/`.
fn storage_prefix(org_id: &str, env_id: &str) -> String {
    format!("org/{org_id}/env/{env_id}/")
}

// Step 5 is the ONLY access gate : the three `require_*_scope`
// helpers used to re-check the JWT scope snapshot (a double gate beside
// `require_policy`); they are now trivial `Ok()` - the enforced Shield
// scope-mirror set decides, keyed on the same action ids the call sites
// evaluate. Kept as functions so call sites and signatures stay stable.
fn require_read_scope(_auth: &crate::auth::AuthContext) -> Result<(), (StatusCode, String)> {
    Ok(())
}

fn require_write_scope(_auth: &crate::auth::AuthContext) -> Result<(), (StatusCode, String)> {
    Ok(())
}

fn require_admin_scope(_auth: &crate::auth::AuthContext) -> Result<(), (StatusCode, String)> {
    Ok(())
}

// ── Object CRUD (env-scoped, env_id from auth context) ─────────────────

/// `PUT /v1/storage/objects/{path}` - upload an object.
#[utoipa::path(
    put,
    operation_id = "object.upload",
    path = "/v1/storage/objects/{object_path}",
    params(("object_path" = String, Path, description = "Object path")),
    request_body = Vec<u8>,
    responses(
        (status = 200, description = "Object uploaded"),
        (status = 403, description = "Missing storage scope"),
    ),
    security(("sentin8:storage:env:write" = [])),
    tag = "storage",
)]
/// Handle PUT object.
pub async fn put_object(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(object_path): Path<String>,
    body: axum::body::Bytes,
) -> Result<Response, (StatusCode, String)> {
    let auth = crate::auth::verify(&state, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &auth,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:storage:env:write"),
    )
    .await?;
    require_write_scope(&auth)?;
    let env_id = auth.env_id();
    let org_id = resolve_org_id(&state.pool, env_id).await?;
    let key = format!(
        "{}{object_path}",
        storage_prefix(&org_id.to_string(), &env_id.to_string())
    );
    let content_type = "application/octet-stream".to_string();
    // Idempotent PUT: content-addressed callers
    // (email8 blobs, etc.) may short-circuit when the object already
    // exists - `If-None-Match: *` or the `X-If-Absent: true` hint
    // skip the payload write entirely (dedup fast path). A mismatched
    // existing object is NOT verified byte-for-byte (content-addressed
    // keys make collisions negligible); the caller opted in.
    let if_absent = headers
        .get("X-If-Absent")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
        || headers
            .get(header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim() == "*")
            .unwrap_or(false);
    if if_absent {
        match state.adapter.exists(&key).await {
            Ok(true) => {
                // Already stored - dedup hit; 200 with the marker so
                // content-addressed callers can skip re-uploads. With the
                // `X-Content-Sha256` header present, verify the stored
                // object's hash before claiming the dedup (opt-in
                // hardening - storage DESIGN §5).
                if let Some(declared) = headers
                    .get("X-Content-Sha256")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string)
                {
                    match state.adapter.get(&key).await {
                        Ok(existing) => {
                            let digest = format!("{:x}", Sha256::digest(existing.as_slice()));
                            if digest != declared {
                                return Err((
                                    StatusCode::CONFLICT,
                                    format!(
                                        "dedup hash mismatch: stored {digest}, declared {declared}"
                                    ),
                                ));
                            }
                        }
                        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
                    }
                }
                return Ok((StatusCode::OK, [("X-Storage-Deduped", "true")]).into_response());
            }
            Ok(false) => {}
            Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
        }
    }
    state
        .adapter
        .put(&key, body.to_vec(), &content_type)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    emit_event(
        &state.pool,
        env_id,
        "sentin8:storage:object:created",
        serde_json::json!({ "key": key, "content_type": content_type, "size": body.len() }),
        &state.config.stream_family,
        crate::auth::raw_bearer_token(&headers),
        Some(auth.sub()),
    )
    .await;
    Ok(StatusCode::OK.into_response())
}

/// `HEAD /v1/storage/objects/{path}` - existence + size probe without
/// reading the payload (the dedup fast path every
/// content-addressed vertical uses before writing).
#[utoipa::path(
    head,
    operation_id = "object.head",
    path = "/v1/storage/objects/{object_path}",
    params(("object_path" = String, Path, description = "Object path")),
    responses(
        (status = 200, description = "Object exists - Content-Length set"),
        (status = 404, description = "Object not found"),
        (status = 403, description = "Missing storage scope"),
    ),
    security(("sentin8:storage:env:read" = [])),
    tag = "storage",
)]
/// Handle head object.
pub async fn head_object(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(object_path): Path<String>,
) -> Result<Response, (StatusCode, String)> {
    let auth = crate::auth::verify(&state, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &auth,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:storage:env:read"),
    )
    .await?;
    require_read_scope(&auth)?;
    let env_id = auth.env_id();
    let org_id = resolve_org_id(&state.pool, env_id).await?;
    let key = format!(
        "{}{object_path}",
        storage_prefix(&org_id.to_string(), &env_id.to_string())
    );
    match state.adapter.size(&key).await {
        Ok(size) => {
            Ok((StatusCode::OK, [(header::CONTENT_LENGTH, size.to_string())]).into_response())
        }
        Err(StorageError::NotFound(_)) => Err((StatusCode::NOT_FOUND, "object not found".into())),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// `GET /v1/storage/objects/{path}` - download an object.
#[utoipa::path(
    get,
    operation_id = "object.download",
    path = "/v1/storage/objects/{object_path}",
    params(("object_path" = String, Path, description = "Object path")),
    responses(
        (status = 200, description = "Object content", body = Vec<u8>),
        (status = 404, description = "Object not found"),
        (status = 403, description = "Missing storage scope"),
    ),
    security(("sentin8:storage:env:read" = [])),
    tag = "storage",
)]
/// Fetch object.
pub async fn get_object(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(object_path): Path<String>,
) -> Result<Response, (StatusCode, String)> {
    let auth = crate::auth::verify(&state, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &auth,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:storage:env:read"),
    )
    .await?;
    require_read_scope(&auth)?;
    let env_id = auth.env_id();
    let org_id = resolve_org_id(&state.pool, env_id).await?;
    let key = format!(
        "{}{object_path}",
        storage_prefix(&org_id.to_string(), &env_id.to_string())
    );
    match state.adapter.get(&key).await {
        Ok(data) => Ok((
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/octet-stream")],
            data,
        )
            .into_response()),
        Err(StorageError::NotFound(_)) => Err((StatusCode::NOT_FOUND, "object not found".into())),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// `DELETE /v1/storage/objects/{path}` - delete an object.
#[utoipa::path(
    delete,
    operation_id = "object.delete",
    path = "/v1/storage/objects/{object_path}",
    params(("object_path" = String, Path, description = "Object path")),
    responses(
        (status = 204, description = "Object deleted"),
        (status = 404, description = "Object not found"),
        (status = 403, description = "Missing storage scope"),
    ),
    security(("sentin8:storage:env:admin" = [])),
    tag = "storage",
)]
/// Delete object.
pub async fn delete_object(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(object_path): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let auth = crate::auth::verify(&state, &headers).await?;
    // Step 5 - Shield decides : delete is the admin action
    // .
    crate::policy::require_policy(
        &state.policy,
        &auth,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:storage:env:admin"),
    )
    .await?;
    require_admin_scope(&auth)?;
    let env_id = auth.env_id();
    let org_id = resolve_org_id(&state.pool, env_id).await?;
    let key = format!(
        "{}{object_path}",
        storage_prefix(&org_id.to_string(), &env_id.to_string())
    );
    state.adapter.delete(&key).await.map_err(|e| match e {
        StorageError::NotFound(_) => (StatusCode::NOT_FOUND, "object not found".into()),
        other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
    })?;
    emit_event(
        &state.pool,
        env_id,
        "sentin8:storage:object:deleted",
        serde_json::json!({ "key": key }),
        &state.config.stream_family,
        crate::auth::raw_bearer_token(&headers),
        Some(auth.sub()),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v1/storage/objects` - list objects with optional prefix.
#[utoipa::path(
    get,
    operation_id = "object.list",
    path = "/v1/storage/objects",
    params(("prefix" = Option<String>, Query, description = "Prefix filter")),
    responses(
        (status = 200, description = "List of objects"),
    ),
    security(("sentin8:storage:env:read" = [])),
    tag = "storage",
)]
/// List objects.
pub async fn list_objects(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(params): axum::extract::Query<ListParams>,
) -> Result<axum::Json<serde_json::Value>, (StatusCode, String)> {
    let auth = crate::auth::verify(&state, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &auth,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:storage:env:read"),
    )
    .await?;
    require_read_scope(&auth)?;
    let env_id = auth.env_id();
    let org_id = resolve_org_id(&state.pool, env_id).await?;
    let prefix = params.prefix.unwrap_or_default();
    let base = format!(
        "{}{prefix}",
        storage_prefix(&org_id.to_string(), &env_id.to_string())
    );
    let objects = state.adapter.list(&base).await.unwrap_or_default();
    Ok(axum::Json(serde_json::json!({"objects": objects})))
}

#[derive(serde::Deserialize, ToSchema)]
/// The listparams type.
pub struct ListParams {
    /// The prefix.
    pub prefix: Option<String>,
}

// ── Signed URLs ────────────────────────────────────────────────────────

/// `POST /v1/storage/objects/{*path}` - dispatch sign-read, sign-upload, copy, move.
#[utoipa::path(
    post,
    operation_id = "object.action",
    path = "/v1/storage/objects/{object_path}",
    params(("object_path" = String, Path, description = "Object path or action (copy/move/sign-read/sign-upload)")),
    responses(
        (status = 200, description = "Action completed"),
        (status = 405, description = "POST not supported on this path"),
        (status = 403, description = "Missing storage scope"),
    ),
    security(("sentin8:storage:env:read" = [])),
    tag = "storage",
)]
/// Handle object action.
pub async fn object_action(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(object_path): Path<String>,
    body: axum::body::Bytes,
) -> Result<Response, (StatusCode, String)> {
    let auth = crate::auth::verify(&state, &headers).await?;
    let env_id = auth.env_id();
    let org_id = resolve_org_id(&state.pool, env_id).await?;
    let org_str = org_id.to_string();
    let env_str = env_id.to_string();
    // Step 5 - Shield decides : copy/move are write actions.
    crate::policy::require_policy(
        &state.policy,
        &auth,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:storage:env:write"),
    )
    .await?;

    if object_path == "copy" || object_path == "move" {
        require_admin_scope(&auth)?;
    } else {
        // sign-read is a read operation; sign-upload issues a write token.
        require_read_scope(&auth)?;
        if object_path.ends_with("/sign-upload") {
            require_write_scope(&auth)?;
        }
    }

    if object_path == "copy" {
        let status = copy_object_inner(&state, &body, &org_str, &env_str).await?;
        emit_event(
            &state.pool,
            env_id,
            "sentin8:storage:object:moved",
            serde_json::json!({"from_key": copy_move_src(&body)?, "to_key": copy_move_dst(&body)?}),
            &state.config.stream_family,
            crate::auth::raw_bearer_token(&headers),
            Some(auth.sub()),
        )
        .await;
        return Ok(status.into_response());
    }
    if object_path == "move" {
        let status = move_object_inner(&state, &body, &org_str, &env_str).await?;
        emit_event(
            &state.pool,
            env_id,
            "sentin8:storage:object:moved",
            serde_json::json!({"from_key": copy_move_src(&body)?, "to_key": copy_move_dst(&body)?}),
            &state.config.stream_family,
            crate::auth::raw_bearer_token(&headers),
            Some(auth.sub()),
        )
        .await;
        return Ok(status.into_response());
    }
    if let Some(stripped) = object_path.strip_suffix("/sign-read") {
        let resp = sign_read_inner(&state, &org_str, &env_str, stripped.to_string()).await?;
        return Ok(resp.into_response());
    }
    if let Some(stripped) = object_path.strip_suffix("/sign-upload") {
        let resp = sign_upload_inner(&state, &org_str, &env_str, stripped.to_string()).await?;
        return Ok(resp.into_response());
    }
    Err((
        StatusCode::METHOD_NOT_ALLOWED,
        "POST not supported on this path; use /sign-read, /sign-upload, /copy, or /move".into(),
    ))
}

fn copy_move_src(body: &axum::body::Bytes) -> Result<String, (StatusCode, String)> {
    let req: CopyMoveRequest = serde_json::from_slice(body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid JSON: {e}")))?;
    Ok(req.src_path)
}

fn copy_move_dst(body: &axum::body::Bytes) -> Result<String, (StatusCode, String)> {
    let req: CopyMoveRequest = serde_json::from_slice(body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid JSON: {e}")))?;
    Ok(req.dst_path)
}

const SIGNED_URL_TTL_SECS: i64 = 3600;

async fn sign_read_inner(
    state: &AppState,
    org_id: &str,
    env_id: &str,
    object_path: String,
) -> Result<axum::Json<serde_json::Value>, (StatusCode, String)> {
    let key = format!("{}{object_path}", storage_prefix(org_id, env_id));
    let token = state
        .signed_codec
        .issue(&key, SIGNED_URL_TTL_SECS, SignedMethod::Get);
    let signed_url = format!("/v1/storage/signed/{token}");
    Ok(axum::Json(serde_json::json!({
        "url": signed_url,
        "expires_in": SIGNED_URL_TTL_SECS,
        "method": "GET",
    })))
}

async fn sign_upload_inner(
    state: &AppState,
    org_id: &str,
    env_id: &str,
    object_path: String,
) -> Result<axum::Json<serde_json::Value>, (StatusCode, String)> {
    let key = format!("{}{object_path}", storage_prefix(org_id, env_id));
    let token = state
        .signed_codec
        .issue(&key, SIGNED_URL_TTL_SECS, SignedMethod::Put);
    let signed_url = format!("/v1/storage/signed/{token}");
    Ok(axum::Json(serde_json::json!({
        "url": signed_url,
        "expires_in": SIGNED_URL_TTL_SECS,
        "method": "PUT",
    })))
}

async fn copy_object_inner(
    state: &AppState,
    body: &axum::body::Bytes,
    org_id: &str,
    env_id: &str,
) -> Result<StatusCode, (StatusCode, String)> {
    let req: CopyMoveRequest = serde_json::from_slice(body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid JSON: {e}")))?;
    let prefix = storage_prefix(org_id, env_id);
    let src = format!("{prefix}{}", req.src_path);
    let dst = format!("{prefix}{}", req.dst_path);
    state
        .adapter
        .copy(&src, &dst)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::OK)
}

async fn move_object_inner(
    state: &AppState,
    body: &axum::body::Bytes,
    org_id: &str,
    env_id: &str,
) -> Result<StatusCode, (StatusCode, String)> {
    let req: CopyMoveRequest = serde_json::from_slice(body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid JSON: {e}")))?;
    let prefix = storage_prefix(org_id, env_id);
    let src = format!("{prefix}{}", req.src_path);
    let dst = format!("{prefix}{}", req.dst_path);
    state
        .adapter
        .move_object(&src, &dst)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::OK)
}

/// Serve or store an object via an HMAC-signed URL token.
/// The token authorizes exactly one method - GET for read tokens, PUT for
/// upload tokens. Signature, expiry and method are all verified; forged
/// tokens yield 403, malformed tokens 400, expired tokens 403.
async fn signed_dispatch(
    state: AppState,
    token: String,
    provided_method: SignedMethod,
    body: Option<axum::body::Bytes>,
) -> Result<Response, (StatusCode, String)> {
    let (key, method) = state.signed_codec.verify(&token).map_err(|e| match e {
        e if e.contains("expired") => (StatusCode::FORBIDDEN, e),
        e if e.contains("signature") => (StatusCode::FORBIDDEN, e),
        e => (StatusCode::BAD_REQUEST, e),
    })?;
    if method != provided_method {
        return Err((
            StatusCode::METHOD_NOT_ALLOWED,
            "signed URL not valid for this method".into(),
        ));
    }
    if provided_method == SignedMethod::Put {
        let bytes = body.ok_or((StatusCode::BAD_REQUEST, "missing request body".into()))?;
        state
            .adapter
            .put(&key, bytes.to_vec(), "application/octet-stream")
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    match state.adapter.get(&key).await {
        Ok(data) => Ok((
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/octet-stream")],
            data,
        )
            .into_response()),
        Err(StorageError::NotFound(_)) => Err((StatusCode::NOT_FOUND, "object not found".into())),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// `GET /v1/storage/signed/{token}` - serve object via signed URL.
#[utoipa::path(
    get,
    operation_id = "signed.serve",
    path = "/v1/storage/signed/{token}",
    params(("token" = String, Path, description = "Signed URL token")),
    responses(
        (status = 200, description = "Object content", body = Vec<u8>),
        (status = 403, description = "Signed URL expired or forged"),
        (status = 400, description = "Invalid token"),
    ),
    tag = "storage",
)]
/// Serve signed.
pub async fn serve_signed(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<Response, (StatusCode, String)> {
    signed_dispatch(state, token, SignedMethod::Get, None).await
}

/// `PUT /v1/storage/signed/{token}` - store object via signed upload URL.
#[utoipa::path(
    put,
    operation_id = "signed.upload",
    path = "/v1/storage/signed/{token}",
    params(("token" = String, Path, description = "Signed URL token")),
    request_body = Vec<u8>,
    responses(
        (status = 200, description = "Object stored", body = Vec<u8>),
        (status = 403, description = "Signed URL expired or forged"),
        (status = 400, description = "Invalid token"),
    ),
    tag = "storage",
)]
/// Handle upload signed.
pub async fn upload_signed(
    State(state): State<AppState>,
    Path(token): Path<String>,
    body: axum::body::Bytes,
) -> Result<Response, (StatusCode, String)> {
    signed_dispatch(state, token, SignedMethod::Put, Some(body)).await
}

// ── Public Read ───────────────────────────────────────────────────────

/// `GET /v1/public/objects/{*path}` - platform-scoped public read for image assets.
/// No auth required. Only serves image extensions. Uses system env storage prefix.
/// Handle public read.
#[utoipa::path(
    get,
    path = "/v1/public/objects/{object_path}",
    params(("object_path" = String, Path, description = "Object key (image assets only)")),
    responses(
        (status = 200, description = "The raw image bytes (Content-Type by extension)"),
        (status = 403, description = "Non-image extension"),
        (status = 404, description = "No such object"),
    ),
    security(),
    tag = "storage",
)]
pub async fn public_read(
    State(state): State<AppState>,
    Path(object_path): Path<String>,
) -> Result<Response, (StatusCode, String)> {
    let ext = object_path.rsplit('.').next().unwrap_or("").to_lowercase();
    if !["svg", "png", "jpg", "jpeg", "gif", "webp", "ico"].contains(&ext.as_str()) {
        return Err((
            StatusCode::FORBIDDEN,
            "only image files are served publicly".into(),
        ));
    }
    // Platform-scoped: use system org/env prefix.
    let org_id = sentin8::config::SYSTEM_ORG_ID.to_string();
    let env_id = sentin8::config::SYSTEM_ENV_ID.to_string();
    let key = format!("{}{object_path}", storage_prefix(&org_id, &env_id));
    serve_image(&state, &key, &ext).await
}

/// `GET /v1/public/env/{env_id}/objects/{*path}` - env-scoped public read.
/// No auth required. Only serves image extensions.
/// Handle public read env.
#[utoipa::path(
    get,
    path = "/v1/public/env/{env_id}/objects/{object_path}",
    params(
        ("env_id" = String, Path, description = "Environment id"),
        ("object_path" = String, Path, description = "Object key (image assets only)")
    ),
    responses(
        (status = 200, description = "The raw image bytes (Content-Type by extension)"),
        (status = 403, description = "Non-image extension"),
        (status = 404, description = "No such object"),
    ),
    security(),
    tag = "storage",
)]
pub async fn public_read_env(
    State(state): State<AppState>,
    Path((env_id, object_path)): Path<(String, String)>,
) -> Result<Response, (StatusCode, String)> {
    let ext = object_path.rsplit('.').next().unwrap_or("").to_lowercase();
    if !["svg", "png", "jpg", "jpeg", "gif", "webp", "ico"].contains(&ext.as_str()) {
        return Err((
            StatusCode::FORBIDDEN,
            "only image files are served publicly".into(),
        ));
    }
    // Resolve org_id from env_id for the storage key prefix.
    let env_uuid = uuid::Uuid::parse_str(&env_id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid env id".into()))?;
    let org_id = resolve_org_id(&state.pool, env_uuid).await?.to_string();
    let key = format!("{}{object_path}", storage_prefix(&org_id, &env_id));
    serve_image(&state, &key, &ext).await
}

async fn serve_image(
    state: &AppState,
    key: &str,
    ext: &str,
) -> Result<Response, (StatusCode, String)> {
    match state.adapter.get(key).await {
        Ok(data) => {
            let content_type = match ext {
                "svg" => "image/svg+xml",
                "png" => "image/png",
                "jpg" | "jpeg" => "image/jpeg",
                "gif" => "image/gif",
                "webp" => "image/webp",
                "ico" => "image/x-icon",
                _ => "application/octet-stream",
            };
            Ok((
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, content_type),
                    (header::CACHE_CONTROL, "public, max-age=3600"),
                ],
                data,
            )
                .into_response())
        }
        Err(StorageError::NotFound(_)) => Err((StatusCode::NOT_FOUND, "object not found".into())),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

// ── Copy/Move ──────────────────────────────────────────────────────────

/// Request body for copy/move operations.
#[derive(Debug, serde::Deserialize, ToSchema)]
/// Request body for copymove.
pub struct CopyMoveRequest {
    /// The src path.
    pub src_path: String,
    /// The dst path.
    pub dst_path: String,
}

/// Emit a storage event through the shared outbox helper. Best-effort:
/// a failed event is logged, never fails the domain operation. Every row
/// carries the publisher's bearer token and subject (bus design ).
async fn emit_event(
    pool: &sqlx::PgPool,
    env_id: uuid::Uuid,
    event_type: &str,
    payload: serde_json::Value,
    stream_family: &str,
    publisher_token: Option<String>,
    publisher_subject: Option<&str>,
) {
    let mut conn = match pool.acquire().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, event_type = %event_type, "storage: failed to acquire connection for outbox event");
            return;
        }
    };
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *conn)
        .await;
    if let Err(e) = sentin8::bus::outbox::insert_outbox_row_with_publisher(
        &mut *conn,
        env_id,
        stream_family,
        event_type,
        &payload,
        publisher_token.as_deref(),
        publisher_subject,
    )
    .await
    {
        tracing::warn!(error = %e, event_type = %event_type, "storage: failed to emit outbox event");
    }
}
