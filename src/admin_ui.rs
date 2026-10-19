// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Storage
// SPDX-License-Identifier: Apache-2.0

//! Sentin8:Storage Admin UI handlers - RFW definitions.
//! Served from `GET /v1/admin/ui/{page}`, rendered by Sentin8:Dash at runtime.

use crate::handlers::AppState;
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use sentin8::rfw::page::*;
use sentin8::rfw::response::AdminUiResponse;
use sentin8::rfw::widget::*;
use serde::Deserialize;

use axum::http::StatusCode;

/// Compute the storage base prefix for the given env scope - the SAME
/// physical layout the object API uses (`org/{org_id}/env/{env_id}/`);
/// org_id is resolved internally from env_id, never from URLs.
async fn storage_base(pool: &sqlx::PgPool, env_id: &str) -> Result<String, (StatusCode, String)> {
    let env_uuid = uuid::Uuid::parse_str(env_id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid env id".into()))?;
    // `sys.environments` is FORCE-RLS'd; the select policy admits the row
    // when the GUC context is initialized with this env id. The context is
    // transaction-local, so the lookup runs inside one explicit transaction
    // (storage DESIGN §6).
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}")))?;
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_uuid)
        .execute(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}")))?;
    let org_id =
        sqlx::query_scalar::<_, uuid::Uuid>("SELECT org_id FROM sys.environments WHERE id = $1")
            .bind(env_uuid)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}")))?
            .ok_or((StatusCode::NOT_FOUND, "environment not found".into()))?;
    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}")))?;
    Ok(format!("org/{org_id}/env/{env_id}/"))
}

/// Compute the full object key within a bucket.
async fn storage_key(
    pool: &sqlx::PgPool,
    env_id: &str,
    bucket: &str,
    object: &str,
) -> Result<String, (StatusCode, String)> {
    Ok(format!(
        "{}{bucket}/{object}",
        storage_base(pool, env_id).await?
    ))
}

/// Resolve the effective env_id for storage operations.
/// Priority: target_env_id query param (BFF proxy) > x-sentin8-env-id header (TLS) > token env_id.
#[derive(Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
/// The targetenvquery type.
pub struct TargetEnvQuery {
    #[serde(default)]
    target_env_id: Option<String>,
}

/// Resolve the effective env and authorize it ( - cross-env access is
/// validated at the authorization layer): if the resolved env differs from
/// the token env, the caller must be a platform admin (`sentin8:sys:admin`) or hold
/// an env-admin scope for the target env. Otherwise 403.
fn resolve_env_id(
    headers: &HeaderMap,
    query: &TargetEnvQuery,
    a: &crate::auth::AuthContext,
) -> Result<String, (StatusCode, String)> {
    let requested = query
        .target_env_id
        .as_deref()
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .or_else(|| {
            headers
                .get("x-sentin8-env-id")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| uuid::Uuid::parse_str(s).ok())
        });
    let token_env = a.env_id();
    match requested {
        Some(env) if env != token_env => {
            if a.has_scope("sentin8:sys:admin")
                || a.has_scope("sentin8:sys:env:admin")
                || a.has_scope("sentin8:sys:org:admin")
            {
                Ok(env.to_string())
            } else {
                Err((
                    StatusCode::FORBIDDEN,
                    "caller has no role in the target environment".into(),
                ))
            }
        }
        _ => Ok(token_env.to_string()),
    }
}

/// Fetch admin ui.
#[utoipa::path(
    get,
    path = "/v1/admin/ui/{page}",
    params(
        ("page" = String, Path, description = "RFW page name"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 200, description = "RFW page definition (rendered by Sentin8:Dash)", body = sentin8::rfw::AdminUiResponse),
        (status = 403, description = "Caller lacks a storage read/admin scope"),
        (status = 404, description = "Unknown page"),
    ),
    security(("sentin8:storage:read" = [])),
    tag = "admin-ui",
)]
pub async fn get_admin_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(page): Path<String>,
    Query(q): Query<TargetEnvQuery>,
) -> Result<Json<AdminUiResponse>, (axum::http::StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    a.require_any_scope(&[
        "sentin8:storage:env:read",
        "sentin8:storage:env:write",
        "sentin8:sys:admin",
        "sentin8:sys:org:admin",
        "sentin8:sys:env:admin",
    ])?;
    // Authorization still resolves+validates the effective env (
    // cross-env rule); the RFW definitions themselves are tenant-agnostic -
    // business params only, the Dash client supplies target_env_id.
    let _ = resolve_env_id(&headers, &q, &a)?;
    let def = match page.as_str() {
        "overview" => AdminPage::new("Storage Overview")
            .widget(card("Summary","Bucket catalog, quota monitoring, object inspection, adapter health.")).build(),
        "buckets" => AdminPage::new("Buckets")
            .action(link("Create Bucket", "buckets/new"))
            .widget(table_with_actions(vec![
                col_s("name","Name",true),
                col_s("objects","Objects",true),
                col_s("size","Size",true),
                col_s("created_at","Created",true),
            ], "/buckets", vec![
                row_action("View", "buckets/{id}"),
                row_action("Upload", "buckets/{id}/upload"),
                row_action_post("Delete", "buckets/{id}/delete"),
            ]))
            .build(),
        "buckets/new" => AdminPage::new("Create Bucket")
            .widget(RemoteWidget::Form(WidgetForm {
                fields: vec![
                    WidgetFormField {
                        key: "name".into(),
                        label: "Bucket Name".into(),
                        field_type: FormFieldType::Text,
                        required: true,
                        placeholder: Some("e.g. logos".into()),
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: Some("The bucket name. Used as a prefix for object keys.".into()),
                        visible_if: None,
                    },
                ],
                submit_endpoint: "/v1/admin/buckets".into(),
                submit_label: "Create Bucket".into(),
                cancel_label: "Cancel".into(),
                method: FormMethod::Post,
            }))
            .build(),
        _ if page.starts_with("buckets/") && !page.ends_with("/download") && !page.ends_with("/link") && !page.contains("/objects/") => {
            let is_upload_page = page.ends_with("/upload");
            let bucket_name = if is_upload_page {
                page.strip_prefix("buckets/").unwrap_or("").strip_suffix("/upload").unwrap_or("")
            } else {
                page.strip_prefix("buckets/").unwrap_or("")
            };
 // RFW data endpoints carry ONLY business params - the Dash
 // ApiClient appends target_env_id to every proxied request
 // (apps/dash/lib/services.dart _buildUrl); embedding it here
 // too duplicates the param and serde rejects the query with
 // 400.
            let data_endpoint = format!("/buckets/objects?bucket={bucket_name}");
 // Upload form - shown inline on the bucket detail page AND on the
 // dedicated upload page. On the bucket detail page, it appears
 // above the objects table.
            let upload_form = RemoteWidget::Form(WidgetForm {
                fields: vec![
                    WidgetFormField {
                        key: "bucket".into(),
                        label: "Bucket".into(),
                        field_type: FormFieldType::Hidden,
                        required: true,
                        placeholder: None,
                        default_value: Some(serde_json::json!(bucket_name)),
                        options: None,
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "file".into(),
                        label: "Select File".into(),
                        field_type: FormFieldType::File,
                        required: true,
                        placeholder: None,
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                ],
                submit_endpoint: "/v1/admin/buckets/upload".into(),
                submit_label: "Upload".into(),
                cancel_label: "Cancel".into(),
                method: FormMethod::Post,
            });
            if is_upload_page {
 // Dedicated upload page - just the form.
                AdminPage::new(format!("Upload to: {bucket_name}"))
                    .widget(upload_form)
                    .build()
            } else {
 // Bucket detail page - upload form inline + objects table.
                AdminPage::new(format!("Bucket: {bucket_name}"))
                    .widgets(vec![
                        upload_form,
                        table_with_actions(vec![
                            col_s("name","Name",true),
                            col_s("size","Size",true),
                            col_s("modified","Modified",true),
                        ], &data_endpoint, vec![
                            row_action("Download", "buckets/{id}/download?object={name}"),
                            row_action_post("Link", "buckets/{id}/link?object={name}"),
                            row_action_post("Delete", "buckets/{id}/objects/{name}/delete"),
                        ]),
                    ])
                    .build()
            }
        },
        "settings" => AdminPage::new("Storage Settings")
            .widget(card("Adapter Configuration","S3-compatible adapter settings (endpoint, region, bucket prefix). Configured via environment variables on the Storage service."))
            .build(),
 // ── Policy Studio - shared page
 // constructors; the guard guarantees `Some` ( dispatch).
        p if sentin8::rfw::policy_page("sentin8:storage", p).is_some() => sentin8::rfw
            ::policy_page("sentin8:storage", p)
            .expect("policy_page checked in guard")
            .build(),
        _ => return Err((axum::http::StatusCode::NOT_FOUND, format!("Unknown admin UI page: {page}"))),
    };
    Ok(Json(AdminUiResponse::page(def)))
}

/// `GET /v1/admin/{resource}` - returns a JSON array of admin data rows.
#[utoipa::path(
    get,
    path = "/v1/admin/{resource}",
    params(
        ("resource" = String, Path, description = "Admin data resource"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 200, description = "The resource's rows for the RFW table", body = sentin8::rfw::policy_pages::AdminDataRows),
        (status = 403, description = "Caller lacks a storage read/admin scope"),
        (status = 404, description = "Unknown resource"),
    ),
    security(("sentin8:storage:read" = [])),
    tag = "admin-ui",
)]
pub async fn get_admin_data(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(resource): Path<String>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    a.require_any_scope(&[
        "sentin8:storage:env:read",
        "sentin8:storage:env:write",
        "sentin8:sys:admin",
        "sentin8:sys:org:admin",
        "sentin8:sys:env:admin",
    ])?;
    let env_id = resolve_env_id(&headers, &q, &a)?;
    let rows: Vec<serde_json::Value> = match resource.as_str() {
        "buckets" => {
            // List top-level "buckets" - these are top-level prefixes under
            // the storage base path (env-scoped).
            let base = storage_base(&state.pool, &env_id).await?;
            let objects = state.adapter.list(&base).await.unwrap_or_default();
            // Group by first path segment (the bucket name).
            let mut buckets: std::collections::HashMap<String, (usize, u64)> =
                std::collections::HashMap::new();
            for obj in &objects {
                let key = obj.strip_prefix(&base).unwrap_or(obj);
                let first_seg = key.split('/').next().unwrap_or(key);
                let entry = buckets.entry(first_seg.to_string()).or_insert((0, 0));
                entry.0 += 1;
                // We don't have size info from list, use 0.
            }
            buckets
                .into_iter()
                .map(|(name, (count, _size))| {
                    serde_json::json!({
                        "id": name,
                        "name": name,
                        "objects": count,
                        "size": "-",
                        "created_at": "-",
                    })
                })
                .collect()
        }
        "buckets/objects" => {
            // List objects in a bucket - bucket name from query param.
            // The RFW data_endpoint includes ?bucket={id}&target_env_id=...
            // But the admin data endpoint only gets the resource path.
            // We list all objects under the storage base scope.
            let base = storage_base(&state.pool, &env_id).await?;
            let objects = state.adapter.list(&base).await.unwrap_or_default();
            objects
                .into_iter()
                .map(|obj| {
                    let name = obj.strip_prefix(&base).unwrap_or(&obj).to_string();
                    serde_json::json!({
                        "id": name,
                        "name": name,
                        "size": "-",
                        "modified": "-",
                    })
                })
                .collect()
        }
        _ => vec![],
    };
    Ok(Json(serde_json::Value::Array(rows)))
}

/// `GET /v1/admin/buckets` - list buckets (top-level prefixes).
/// This is a dedicated handler because the route `/v1/admin/buckets` also
/// has a POST handler, so the catch-all `/v1/admin/{resource}` route is
/// shadowed for GET requests.
/// List buckets.
#[utoipa::path(
    get,
    path = "/v1/admin/buckets",
    params(("target_env_id" = String, Query, description = "Target env (RLS context)")),
    responses(
        (status = 200, description = "Bucket names + object counts", body = sentin8::rfw::policy_pages::AdminDataRows),
    ),
    security(("sentin8:storage:read" = [])),
    tag = "admin-ui",
)]
pub async fn list_buckets(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    a.require_any_scope(&[
        "sentin8:storage:env:read",
        "sentin8:storage:env:write",
        "sentin8:sys:admin",
        "sentin8:sys:org:admin",
        "sentin8:sys:env:admin",
    ])?;
    let env_id = resolve_env_id(&headers, &q, &a)?;
    let base = storage_base(&state.pool, &env_id).await?;
    let objects = state.adapter.list(&base).await.unwrap_or_default();
    let mut buckets: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for obj in &objects {
        let key = obj.strip_prefix(&base).unwrap_or(obj);
        let first_seg = key.split('/').next().unwrap_or(key);
        *buckets.entry(first_seg.to_string()).or_insert(0) += 1;
    }
    let rows: Vec<serde_json::Value> = buckets
        .into_iter()
        .map(|(name, count)| {
            serde_json::json!({
                "id": name,
                "name": name,
                "objects": count,
                "size": "-",
                "created_at": "-",
            })
        })
        .collect();
    Ok(Json(serde_json::Value::Array(rows)))
}

#[derive(Deserialize)]
/// The bucketobjectsquery type.
pub struct BucketObjectsQuery {
    /// The bucket.
    pub bucket: String,
}

/// `GET /v1/admin/buckets/objects?bucket=name` - list objects in a bucket.
/// List bucket objects.
#[utoipa::path(
    get,
    path = "/v1/admin/buckets/objects",
    params(
        ("bucket" = String, Query, description = "Bucket name"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 200, description = "Objects in the bucket", body = sentin8::rfw::policy_pages::AdminDataRows),
        (status = 404, description = "Unknown bucket"),
    ),
    security(("sentin8:storage:read" = [])),
    tag = "admin-ui",
)]
pub async fn list_bucket_objects(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Query(params): Query<BucketObjectsQuery>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    a.require_any_scope(&[
        "sentin8:storage:env:read",
        "sentin8:storage:env:write",
        "sentin8:sys:admin",
        "sentin8:sys:org:admin",
        "sentin8:sys:env:admin",
    ])?;
    let env_id = resolve_env_id(&headers, &q, &a)?;
    let bucket_base = storage_base(&state.pool, &env_id).await?;
    let base = format!("{}{}/", bucket_base, params.bucket);
    let objects = state.adapter.list(&base).await.unwrap_or_default();
    let rows: Vec<serde_json::Value> = objects
        .into_iter()
        .map(|obj| {
            let name = obj.strip_prefix(&base).unwrap_or(&obj).to_string();
            serde_json::json!({
                "id": name,
                "name": name,
                "size": "-",
                "modified": "-",
            })
        })
        .collect();
    Ok(Json(serde_json::Value::Array(rows)))
}

#[derive(Deserialize, utoipa::ToSchema)]
/// Request body for uploadfile.
pub struct UploadFileRequest {
    /// The bucket.
    pub bucket: String,
    /// The file name.
    pub file_name: String,
    /// The content base64.
    pub content_base64: String,
}

/// `POST /v1/admin/buckets/upload` - upload a file to a bucket.
/// Handle upload file.
#[utoipa::path(
    post,
    path = "/v1/admin/buckets/upload",
    params(("target_env_id" = String, Query, description = "Target env (RLS context)")),
    request_body = UploadFileRequest,
    responses(
        (status = 200, description = "File stored (multipart or JSON body per the RFW form)", body = sentin8::rfw::policy_pages::AdminRedirectAck),
    ),
    security(("sentin8:storage:write" = [])),
    tag = "admin-ui",
)]

pub async fn upload_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Json(req): Json<UploadFileRequest>,
) -> Result<Json<AdminUiResponse>, (axum::http::StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    a.require_any_scope(&[
        "sentin8:storage:env:write",
        "sentin8:sys:admin",
        "sentin8:sys:org:admin",
        "sentin8:sys:env:admin",
    ])?;
    let env_id = resolve_env_id(&headers, &q, &a)?;

    // Decode base64 content.
    use base64::Engine;
    let content = base64::engine::general_purpose::STANDARD
        .decode(&req.content_base64)
        .map_err(|e| {
            (
                axum::http::StatusCode::BAD_REQUEST,
                format!("Invalid base64: {e}"),
            )
        })?;

    let key = storage_key(&state.pool, &env_id, &req.bucket, &req.file_name).await?;
    state
        .adapter
        .put(&key, content, "application/octet-stream")
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("Upload failed: {e}"),
            )
        })?;

    Ok(Json(AdminUiResponse::redirect(format!(
        "buckets/{}",
        req.bucket
    ))))
}

#[derive(Deserialize, utoipa::ToSchema)]
/// Request body for createbucket.
pub struct CreateBucketRequest {
    /// The name.
    pub name: String,
}

/// `POST /v1/admin/buckets` - create a bucket by placing a `.keep` marker
/// object at the bucket path. Returns an RFW redirect to the buckets list.
/// Create bucket.
#[utoipa::path(
    post,
    path = "/v1/admin/buckets",
    params(("target_env_id" = String, Query, description = "Target env (RLS context)")),
    request_body = CreateBucketRequest,
    responses(
        (status = 200, description = "Bucket created (.keep marker written)", body = sentin8::rfw::policy_pages::AdminRedirectAck),
    ),
    security(("sentin8:storage:write" = [])),
    tag = "admin-ui",
)]

pub async fn create_bucket(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Json(req): Json<CreateBucketRequest>,
) -> Result<Json<AdminUiResponse>, (axum::http::StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    a.require_any_scope(&[
        "sentin8:storage:env:write",
        "sentin8:sys:admin",
        "sentin8:sys:org:admin",
        "sentin8:sys:env:admin",
    ])?;
    let env_id = resolve_env_id(&headers, &q, &a)?;

    // Sanitize bucket name - only allow alphanumeric, dash, underscore.
    let name = req.name.trim();
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            "Invalid bucket name. Use only letters, numbers, dashes, and underscores.".into(),
        ));
    }

    // Create a placeholder object to establish the bucket prefix.
    let key = storage_key(&state.pool, &env_id, name, ".keep").await?;
    tracing::info!(key = %key, env_id = %env_id, "create_bucket: put");
    state
        .adapter
        .put(&key, Vec::new(), "application/octet-stream")
        .await
        .map_err(|e| {
            tracing::error!(error = %e, key = %key, "create_bucket: put FAILED");
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to create bucket: {e}"),
            )
        })?;

    Ok(Json(AdminUiResponse::redirect("buckets")))
}

#[derive(Deserialize, utoipa::ToSchema)]
/// Request body for deletebucket.
pub struct DeleteBucketRequest {
    /// Identifier.
    pub id: String,
}

/// `POST /v1/admin/buckets/{id}/delete` - delete a bucket and all its objects.
/// Delete bucket.
#[utoipa::path(
    post,
    path = "/v1/admin/buckets/{id}/delete",
    params(
        ("id" = String, Path, description = "Bucket name"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 200, description = "Bucket deleted with all objects", body = sentin8::rfw::policy_pages::AdminRedirectAck),
        (status = 404, description = "Unknown bucket"),
    ),
    security(("sentin8:storage:write" = [])),
    tag = "admin-ui",
)]

pub async fn delete_bucket(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Json(req): Json<DeleteBucketRequest>,
) -> Result<Json<AdminUiResponse>, (axum::http::StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    a.require_any_scope(&[
        "sentin8:storage:env:write",
        "sentin8:sys:admin",
        "sentin8:sys:org:admin",
        "sentin8:sys:env:admin",
    ])?;
    let env_id = resolve_env_id(&headers, &q, &a)?;
    let bucket_base = storage_base(&state.pool, &env_id).await?;
    let prefix = format!("{}{}/", bucket_base, req.id);
    let objects = state.adapter.list(&prefix).await.unwrap_or_default();
    for obj in &objects {
        let _ = state.adapter.delete(obj).await;
    }
    Ok(Json(AdminUiResponse::redirect("buckets")))
}

#[derive(Deserialize, utoipa::ToSchema)]
/// Request body for deleteobject.
pub struct DeleteObjectRequest {
    /// The object.
    pub object: String,
}

/// `POST /v1/admin/buckets/{id}/objects/{object}/delete` - delete a single object.
/// Delete object.
#[utoipa::path(
    post,
    path = "/v1/admin/buckets/{id}/objects/{object}/delete",
    params(
        ("id" = String, Path, description = "Bucket name"),
        ("object" = String, Path, description = "Object key"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 200, description = "Object deleted", body = AdminUiResponse),
        (status = 404, description = "Unknown bucket or object"),
    ),
    security(("sentin8:storage:write" = [])),
    tag = "admin-ui",
)]

pub async fn delete_object(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path((bucket_id, object_name)): Path<(String, String)>,
) -> Result<Json<AdminUiResponse>, (axum::http::StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    a.require_any_scope(&[
        "sentin8:storage:env:write",
        "sentin8:sys:admin",
        "sentin8:sys:org:admin",
        "sentin8:sys:env:admin",
    ])?;
    let env_id = resolve_env_id(&headers, &q, &a)?;
    let key = storage_key(&state.pool, &env_id, &bucket_id, &object_name).await?;
    state.adapter.delete(&key).await.map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Delete failed: {e}"),
        )
    })?;
    Ok(Json(AdminUiResponse::redirect(format!(
        "buckets/{bucket_id}"
    ))))
}

/// `GET /v1/admin/buckets/{id}/download?object={name}` - download an object.
/// Returns the raw bytes as a binary stream.
/// Handle download object.
#[utoipa::path(
    get,
    path = "/v1/admin/buckets/{id}/download",
    params(
        ("id" = String, Path, description = "Bucket name"),
        ("object" = String, Query, description = "Object key"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 200, description = "The raw object bytes"),
        (status = 404, description = "Unknown bucket or object"),
    ),
    security(("sentin8:storage:read" = [])),
    tag = "admin-ui",
)]

pub async fn download_object(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(bucket_id): Path<String>,
    Query(params): Query<DeleteObjectRequest>,
) -> Result<axum::response::Response, (axum::http::StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    a.require_any_scope(&[
        "sentin8:storage:env:read",
        "sentin8:storage:env:write",
        "sentin8:sys:admin",
        "sentin8:sys:org:admin",
        "sentin8:sys:env:admin",
    ])?;
    let env_id = resolve_env_id(&headers, &q, &a)?;
    let key = storage_key(&state.pool, &env_id, &bucket_id, &params.object).await?;
    let data = state.adapter.get(&key).await.map_err(|e| {
        (
            axum::http::StatusCode::NOT_FOUND,
            format!("Object not found: {e}"),
        )
    })?;
    Ok(axum::response::Response::builder()
        .status(axum::http::StatusCode::OK)
        .header("Content-Type", "application/octet-stream")
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", params.object),
        )
        .body(axum::body::Body::from(data))
        .unwrap())
}

#[derive(Deserialize)]
/// Request body for generatelink.
/// The signed-read-URL reply.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct GenerateLinkResponse {
    /// The signed read URL (expiring token embedded).
    pub url: String,
    /// The URL's lifetime in seconds.
    pub expires_in: i32,
    /// The method the URL answers.
    pub method: String,
}

#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
/// The body of the link request.
pub struct GenerateLinkRequest {
    /// The object.
    pub object: String,
}

/// `POST /v1/admin/buckets/{id}/link` - generate a signed read URL for an object.
/// Generate link.
#[utoipa::path(
    post,
    path = "/v1/admin/buckets/{id}/link",
    params(
        ("id" = String, Path, description = "Bucket name"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    request_body = GenerateLinkRequest,
    responses(
        (status = 200, description = "Signed read URL for the object", body = GenerateLinkResponse),
        (status = 404, description = "Unknown bucket or object"),
    ),
    security(("sentin8:storage:write" = [])),
    tag = "admin-ui",
)]

pub async fn generate_link(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(bucket_id): Path<String>,
    Json(req): Json<GenerateLinkRequest>,
) -> Result<Json<GenerateLinkResponse>, (axum::http::StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    a.require_any_scope(&[
        "sentin8:storage:env:read",
        "sentin8:storage:env:write",
        "sentin8:sys:admin",
        "sentin8:sys:org:admin",
        "sentin8:sys:env:admin",
    ])?;
    let env_id = resolve_env_id(&headers, &q, &a)?;
    let key = storage_key(&state.pool, &env_id, &bucket_id, &req.object).await?;

    // Generate a signed read token (same HMAC codec as handlers.rs).
    let token = state
        .signed_codec
        .issue(&key, 3600, crate::storage::SignedMethod::Get);

    Ok(Json(GenerateLinkResponse {
        url: format!("/v1/storage/signed/{token}"),
        expires_in: 3600,
        method: "GET".to_string(),
    }))
}
#[allow(dead_code)]
fn col(key: &str, label: &str) -> WidgetDataTableColumn {
    WidgetDataTableColumn {
        key: key.into(),
        label: label.into(),
        sortable: false,
        width: None,
        format: None,
    }
}
fn col_s(key: &str, label: &str, sortable: bool) -> WidgetDataTableColumn {
    WidgetDataTableColumn {
        key: key.into(),
        label: label.into(),
        sortable,
        width: None,
        format: None,
    }
}
#[allow(dead_code)]
fn cols(key: &str, label: &str) -> WidgetDataTableColumn {
    col_s(key, label, true)
}
fn table_with_actions(
    columns: Vec<WidgetDataTableColumn>,
    endpoint: &str,
    row_actions: Vec<WidgetButton>,
) -> RemoteWidget {
    RemoteWidget::DataTable(WidgetDataTable {
        columns,
        data_endpoint: endpoint.into(),
        sortable: true,
        filterable: true,
        page_size: 20,
        empty_message: Some("No data.".into()),
        row_link: None,
        row_actions,
    })
}
fn row_action(label: &str, route: &str) -> WidgetButton {
    WidgetButton {
        label: label.into(),
        button_type: ButtonType::Link,
        route: Some(route.into()),
        endpoint: None,
        icon: None,
    }
}
fn row_action_post(label: &str, endpoint: &str) -> WidgetButton {
    WidgetButton {
        label: label.into(),
        button_type: ButtonType::Primary,
        route: None,
        endpoint: Some(endpoint.into()),
        icon: None,
    }
}
fn card(title: &str, body: &str) -> RemoteWidget {
    RemoteWidget::Card(WidgetCard {
        title: Some(title.into()),
        subtitle: None,
        children: vec![RemoteWidget::Text(WidgetText {
            text: body.into(),
            text_type: WidgetTextType::Body,
            align: TextAlign::Left,
            max_lines: None,
        })],
        actions: vec![],
    })
}
fn link(label: &str, route: &str) -> AdminUiAction {
    AdminUiAction {
        label: label.into(),
        action_type: AdminUiActionType::Link,
        route: Some(route.into()),
        endpoint: None,
        icon: Some("0xe145".into()),
    }
}
