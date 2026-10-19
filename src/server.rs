// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Storage
// SPDX-License-Identifier: Apache-2.0

//! Axum server setup for Sentin8:Storage.

use std::sync::Arc;

use axum::routing::{get, post};

use crate::handlers::{self, AppState};
use crate::storage::{LocalFsAdapter, StorageAdapter};

/// Build state.
pub async fn build_state(
    core: sentin8::shell::ServiceCore,
) -> anyhow::Result<crate::handlers::AppState> {
    let config = crate::config::StorageConfig::from_env();
    let adapter: Arc<dyn StorageAdapter> = Arc::new(LocalFsAdapter::new(&config.local_root));
    let signed_codec = Arc::new(crate::storage::SignedUrlCodec::new(&config.signing_key));
    // ── Sentin8:Policy (- shell-owned boot): consume the
    // engine the shell booted in step 8 - no second engine, consumer, or
    // DCR registration here.
    let policy_engine = core.admin.policy.clone();

    let state = AppState {
        signed_codec,
        config: Arc::new(config.clone()),
        adapter,
        pool: core.pool.clone(),
        policy: policy_engine.clone(),
        admin: sentin8::shield::admin::SharedAdminState {
            service: "sentin8:storage".to_string(),
            pool: core.pool.clone(),
            policy: policy_engine.clone(),
            auth_client: Arc::new(config.auth_client.clone()),
        },
        // Boot-loaded platform workload registry map (auth DESIGN §4.3f;
        // DESIGN §5 certificate fallback). Fail-open-with-warning at
        // boot: the bearer path (user/delegated) still serves while
        // certificate-workload calls fail-closed until the map loads.
        workload_registry: match sentin8::auth::workload_registry::WorkloadMap::boot_load(
            "sentin8:storage",
        )
        .await
        {
            Ok(map) => map,
            Err(e) => {
                tracing::warn!(error = %e, "storage: workload registry map unavailable at boot - certificate-workload calls fail-closed until next boot");
                sentin8::auth::workload_registry::WorkloadMap::boot_load_empty("sentin8:storage")
            }
        },
    };

    Ok(state)
}

/// Add this service's routes onto the shell-provided router. The shell
/// owns the boot sequence, state binding, OpenAPI merge and the standard
/// middleware stack; this adds ONLY routes (including the service's own
/// `/v1/health` - custom payload).
/// Handle routes.
pub fn routes(
    router: axum::Router<crate::handlers::AppState>,
) -> axum::Router<crate::handlers::AppState> {
    router
        .route("/v1/health", get(handlers::health))
        // ── Admin UI (RFW) ─────────────────────────────────────────────────
        .route("/v1/admin/ui/{*page}", get(crate::admin_ui::get_admin_ui))
        .route("/v1/admin/{resource}", get(crate::admin_ui::get_admin_data))
        .route(
            "/v1/admin/buckets",
            get(crate::admin_ui::list_buckets).post(crate::admin_ui::create_bucket),
        )
        .route(
            "/v1/admin/buckets/upload",
            post(crate::admin_ui::upload_file),
        )
        .route(
            "/v1/admin/buckets/objects",
            get(crate::admin_ui::list_bucket_objects),
        )
        .route(
            "/v1/admin/buckets/{id}/delete",
            post(crate::admin_ui::delete_bucket),
        )
        .route(
            "/v1/admin/buckets/{id}/objects/{object}/delete",
            post(crate::admin_ui::delete_object),
        )
        .route(
            "/v1/admin/buckets/{id}/download",
            get(crate::admin_ui::download_object),
        )
        .route(
            "/v1/admin/buckets/{id}/link",
            post(crate::admin_ui::generate_link),
        )
        // Environment namespace - env_id is resolved from TLS context
        // headers (X-Sentin8-Env-Id), not from URL path params.
        //
        // The object path is matched as a single catch-all segment and
        // dispatched to the right handler based on (HTTP method, URL
        // path suffix).
        //
        // GET /v1/.../objects/<path> → get_object
        // PUT /v1/.../objects/<path> → put_object
        // DELETE /v1/.../objects/<path> → delete_object
        // POST /v1/.../objects/<path>/sign-read → sign_read
        // POST /v1/.../objects/<path>/sign-upload → sign_upload
        // POST /v1/.../objects/<path> → copy_object or move_object
        // (only if last segment is /copy or /move)
        .route(
            "/v1/storage/objects/{*object_path}",
            get(handlers::get_object)
                .put(handlers::put_object)
                .head(handlers::head_object)
                .delete(handlers::delete_object)
                .post(handlers::object_action),
        )
        .route("/v1/storage/objects", get(handlers::list_objects))
        // Signed URL serving - GET for read tokens, PUT for upload tokens.
        .route(
            "/v1/storage/signed/{token}",
            get(handlers::serve_signed).put(handlers::upload_signed),
        )
        // Public read - env-scoped (env_id from path for public access)
        .route(
            "/v1/public/env/{env_id}/objects/{*object_path}",
            get(handlers::public_read_env),
        )
        // Public read - platform-scoped (system env, e.g. branding logos)
        .route(
            "/v1/public/objects/{*object_path}",
            get(handlers::public_read),
        )
        // Traffic counter - counts every inbound request (excludes health checks).
        // ── Sentin8:Policy admin API ( - shared implementation,
        // one surface per service; handlers are generic over this AppState).
        .route(
            "/v1/admin/policy-sets",
            get(sentin8::shield::admin::list_policy_sets::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}",
            get(sentin8::shield::admin::get_policy_set::<handlers::AppState>)
                .put(sentin8::shield::admin::put_policy_set::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}/test",
            post(sentin8::shield::admin::test_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/enforce",
            post(sentin8::shield::admin::admin_enforce_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/shadow",
            post(sentin8::shield::admin::admin_shadow_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/disable",
            post(sentin8::shield::admin::admin_disable_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/relations",
            get(sentin8::shield::admin::list_relations::<handlers::AppState>)
                .put(sentin8::shield::admin::put_relation::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_relation::<handlers::AppState>),
        )
        .route(
            "/v1/admin/relations/check",
            get(sentin8::shield::admin::check_relation::<handlers::AppState>),
        )
        .route(
            "/v1/admin/attributes",
            get(sentin8::shield::admin::list_attributes::<handlers::AppState>)
                .put(sentin8::shield::admin::put_attribute::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_attribute::<handlers::AppState>),
        )
}

/// Shared policy-admin surface accessor - the shared
/// handlers extract this service's admin state via [`HasPolicyAdmin`].
impl sentin8::shield::admin::HasPolicyAdmin for AppState {
    fn policy_admin(&self) -> &sentin8::shield::admin::SharedAdminState {
        &self.admin
    }
}
