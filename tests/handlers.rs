// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Storage
// SPDX-License-Identifier: Apache-2.0

//! Handler-level integration tests for Sentin8:Storage (SEC-storage-11).
//!
//! Exercises the full HTTP surface in-process with a locally signed JWT
//! issuer (mock discovery + JWKS over a loopback HTTP server) so the scope
//! matrix, HMAC-signed URLs, dedup headers, path traversal and tenant
//! isolation are covered at the route layer, not just the adapter layer.
//!
//! Tests that need the bus-inbox DB (`env`-scoped org resolution and event
//! emission) use runtime-skip gating (sentin8-testing-strategy.md §3): they
//! print one skip line and pass when PostgreSQL is unreachable. Run the full
//! suite with `make test-rust-integration` after `make infra-up`.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use std::sync::Arc;
use tower::ServiceExt;

use sentin8_storage_server::{
    config::StorageConfig,
    handlers::AppState,
    server::routes,
    storage::{LocalFsAdapter, SignedMethod, SignedUrlCodec, StorageAdapter},
};

// ── Local JWT issuer (mock discovery + JWKS) ────────────────────────────

/// An in-process RSA keypair + loopback HTTP server serving
/// `/.well-known/openid-configuration` and `/.well-known/jwks.json`, so the
/// shared auth client verifies tokens against a locally controlled issuer.
struct TestIssuer {
    base_url: String,
    signing_key: jsonwebtoken::EncodingKey,
    kid: String,
}

/// The Sentin8 HTTP stack (rustls + Graviola) requires the PQ provider
/// installed once per process — same as the storage-client wire tests.
fn install_pq_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = sentin8::tls::crypto::sentin8_pq_provider().install_default();
    });
}

impl TestIssuer {
    async fn start() -> Self {
        // Deterministic 2048-bit RSA keypair for test signing.
        use base64::Engine;
        use rsa::pkcs8::EncodePrivateKey;
        use rsa::traits::PublicKeyParts;
        let mut rng = rand::thread_rng();
        let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
        let pub_key = rsa::RsaPublicKey::from(&priv_key);
        let n = pub_key.n().to_bytes_be();
        let e = pub_key.e().to_bytes_be();
        let n_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&n);
        let e_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&e);
        let kid = "storage-test-key".to_string();
        let pem = priv_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .expect("pem");
        let signing_key = jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_bytes()).expect("key");
        Self::serve(signing_key, kid, n_b64, e_b64).await
    }

    async fn serve(
        signing_key: jsonwebtoken::EncodingKey,
        kid: String,
        n_b64: String,
        e_b64: String,
    ) -> Self {
        install_pq_provider();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().unwrap();
        let kid_jwks = kid.clone();
        let n_jwks = n_b64.clone();
        let e_jwks = e_b64.clone();

        let discovery = serde_json::json!({
            "issuer": format!("http://{addr}"),
            "jwks_uri": format!("http://{addr}/.well-known/jwks.json"),
            "authorization_endpoint": format!("http://{addr}/authorize"),
            "token_endpoint": format!("http://{addr}/token"),
            "response_types_supported": ["code"],
        });
        let jwks = serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "kid": kid_jwks,
                "alg": "RS256",
                "use": "sig",
                "n": n_jwks,
                "e": e_jwks,
            }]
        });

        // /oauth/userinfo — the live-identity endpoint the policy engine's
        // RoleResolver calls (mirrors production Sentin8:Auth). The test
        // issuer holds no RBAC tables, so it echoes the token's own `scope`
        // claim as the effective scope set (the test mints the scopes it
        // wants the principal to hold).
        let app = axum::Router::new()
            .route(
                "/oauth/userinfo",
                axum::routing::get(|headers: axum::http::HeaderMap| async move {
                    let scopes = headers
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.strip_prefix("Bearer "))
                        .and_then(|t| {
                            // Decode the payload segment (no signature check —
                            // the token was minted by this same test issuer).
                            use base64::Engine as _;
                            let seg = t.split('.').nth(1)?;
                            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                                .decode(seg)
                                .ok()?;
                            let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
                            v.get("scope").and_then(|s| s.as_str()).map(str::to_string)
                        })
                        .unwrap_or_default();
                    let list: Vec<String> = scopes.split_whitespace().map(str::to_string).collect();
                    axum::Json(serde_json::json!({
                        "sub": "test-subject",
                        "roles": [],
                        "groups": [],
                        "scopes": list,
                    }))
                }),
            )
            .route(
                "/.well-known/openid-configuration",
                axum::routing::get(move || {
                    let d = discovery.clone();
                    async move { axum::Json(d) }
                }),
            )
            .route(
                "/.well-known/jwks.json",
                axum::routing::get(move || {
                    let j = jwks.clone();
                    async move { axum::Json(j) }
                }),
            );
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let _ = (&n_b64, &e_b64); // served via the JWKS endpoint only
        Self {
            base_url: format!("http://{addr}"),
            signing_key,
            kid,
        }
    }

    /// Mint an RS256 access token with the given claims.
    fn token(&self, sub: &str, env_id: &str, scope: &str, ttl_secs: i64) -> String {
        use jsonwebtoken::Algorithm;
        let now = chrono::Utc::now().timestamp();
        let claims = serde_json::json!({
            "sub": sub,
            "iss": self.base_url,
            "aud": "sentin8",
            "jti": uuid::Uuid::new_v4().to_string(),
            "iat": now,
            "exp": now + ttl_secs,
            "token_tp": "access",
            "scope": scope,
            "env_id": env_id,
        });
        let header = jsonwebtoken::Header {
            alg: Algorithm::RS256,
            kid: Some(self.kid.clone()),
            ..Default::default()
        };
        jsonwebtoken::encode(&header, &claims, &self.signing_key).expect("sign jwt")
    }
}

// ── Test harness ────────────────────────────────────────────────────────

/// An env UUID that does not exist — org resolution must fail closed
/// (404), never fall back to the system org (SEC-storage-4).
const ENV_UNKNOWN: &str = "99999999-9999-9999-9999-999999999999";

/// Per-process shared fixture: the test tenant env UUID. Each test run
/// provisions its own throwaway org + env (repo convention — see
/// `services/app/tests/integration.rs`) so the suite never depends on
/// externally seeded state surviving a DB reset.
static TEST_ENV: tokio::sync::OnceCell<String> = tokio::sync::OnceCell::const_new();

async fn mk_env_id(pool: &sqlx::PgPool) -> String {
    TEST_ENV
        .get_or_init(|| async {
            let env_id = uuid::Uuid::new_v4();
            let org_id = uuid::Uuid::new_v4();
            let mut tx = pool
                .begin()
                .await
                .expect("test harness: begin provisioning tx");
            sqlx::query(
                r#"INSERT INTO sys.organizations (id, slug, display_name, domain)
                   VALUES ($1, $2, $3, $4)"#,
            )
            .bind(org_id)
            .bind(format!("org-{}", org_id.simple()))
            .bind(format!("Storage Test Org {}", org_id.simple()))
            .bind(format!("org-{}.test", org_id.simple()))
            .execute(&mut *tx)
            .await
            .expect("test harness: provision org");
            sqlx::query(
                r#"INSERT INTO sys.environments (id, org_id, slug, display_name)
                   VALUES ($1, $2, $3, $4)"#,
            )
            .bind(env_id)
            .bind(org_id)
            .bind(format!("env-{}", env_id.simple()))
            .bind(format!("Storage Test Env {}", env_id.simple()))
            .execute(&mut *tx)
            .await
            .expect("test harness: provision env");
            tx.commit()
                .await
                .expect("test harness: commit provisioning");
            env_id.to_string()
        })
        .await
        .clone()
}

/// A token for an unknown env is rejected — object writes under an
/// unresolvable tenant must fail closed, not silently land under the
/// system org's namespace.
#[tokio::test]
async fn unknown_env_fails_closed() {
    let Some((app, issuer, _tmp, env)) = spawn_app().await else {
        return;
    };
    let tok = issuer.token(
        "user1",
        ENV_UNKNOWN,
        "sentin8:storage:env:read sentin8:storage:env:write sentin8:storage:env:admin",
        300,
    );
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/storage/objects/should-not-exist.txt")
                .header("authorization", format!("Bearer {tok}"))
                .body(Body::from(b"data".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    // Step 5 is the FIRST gate after verification: the unknown env resolves
    // no live identity (userinfo lookup for that env fails → empty live
    // scopes) and the enforced scope-mirror denies. Fail-closed 403 — the
    // request never reaches tenant resolution (404).
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "unknown env must fail closed: {}",
        body_string(resp).await
    );
    // The object was not created under the system org either.
    let sys_tok = issuer.token(
        &format!("user-{}", uuid::Uuid::new_v4()),
        env.as_str(),
        "sentin8:storage:env:read",
        300,
    );
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/storage/objects/should-not-exist.txt")
                .header("authorization", format!("Bearer {sys_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// Build the storage router with a tempdir-backed adapter, a test issuer,
/// and the real pool for org resolution + event emission. Returns `None`
/// (one skip line per process) only when PostgreSQL is unreachable — the
/// `cargo test` default `make test-rust` path without `make infra-up`.
async fn spawn_app() -> Option<(axum::Router, TestIssuer, tempfile::TempDir, String)> {
    install_pq_provider();
    // Test binaries don't run the shell boot sequence — load the repo .env
    // (DATABASE_URL) explicitly. Already-loaded vars are not overwritten.
    let _ = dotenvy::dotenv();
    let issuer = TestIssuer::start().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let adapter: Arc<dyn sentin8_storage_server::storage::StorageAdapter> =
        Arc::new(LocalFsAdapter::new(tmp.path()));

    // Auth client pointed at the local issuer.
    let auth_client = sentin8::auth::client::Client::new(sentin8::auth::client::ClientOptions {
        base_url: issuer.base_url.clone(),
        ..Default::default()
    });

    let config = StorageConfig {
        port: 0,
        storage_adapter: "local".into(),
        local_root: tmp.path().to_string_lossy().to_string(),
        sentin8_auth_jwks_url: format!("{}/.well-known/jwks.json", issuer.base_url),
        sentin8_auth_issuer: issuer.base_url.clone(),
        auth_client,
        database_url: std::env::var("DATABASE_URL").unwrap_or_default(),
        sentin8_bus_url: String::new(),
        stream_family: "storage".into(),
        signing_key: b"test-signing-key".to_vec(),
    };

    // Pool: real DB when reachable (org resolution + events). An empty
    // DATABASE_URL is treated as unreachable — never a silent skip.
    if config.database_url.trim().is_empty() {
        eprintln!(
            "skipping DB-backed storage handler tests — DATABASE_URL not set (run with `make infra-up` first)"
        );
        return None;
    }
    let pool = match sqlx::PgPool::connect(&config.database_url).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("skipping DB-backed storage handler tests — PostgreSQL unreachable: {e}");
            return None;
        }
    };
    // Provision (once per process) the throwaway org+env the tests use.
    let env_id = mk_env_id(&pool).await;

    // Engine seeded with the enforced scope-mirror set for THIS test env —
    // mirrors production (enroll seeds the enforced set per env; the
    // fail-closed empty-env deny would otherwise reject every request).
    // §4.2b: the shim engine() is test-only-in-lib; production gets the
    // engine from the shell boot — tests build it via the same factory.
    let engine = sentin8::shield::runtime::engine_for("sentin8:storage");
    seed_storage_scope_mirror(
        &engine,
        &uuid::Uuid::parse_str(&env_id).expect("test env uuid"),
    );
    // Persist the seeded set so the sync-reload-on-empty-coverage path
    // (any env without cached coverage triggers one `sentin8_boot_policy_load`
    // pass, which REPLACES the whole cache) cannot wipe the in-memory seed
    // mid-test. Production parity: enroll writes the same row to
    // `sys.policy_sets`; the hot-reload consumer then pushes it into every
    // engine. The insert mirrors the engine seed exactly (same service/
    // name/policies, platform origin, enforced).
    seed_storage_scope_mirror_row(
        &pool,
        &uuid::Uuid::parse_str(&env_id).expect("test env uuid"),
    )
    .await;
    // Point the live-identity resolver at the test issuer (its userinfo
    // endpoint echoes the token's scope claim — mirrors production Auth).
    sentin8::shield::runtime::init_shared_deps(&issuer.base_url, pool.clone());
    let state = AppState {
        config: Arc::new(config),
        adapter,
        pool: pool.clone(),
        signed_codec: Arc::new(SignedUrlCodec::new(b"test-signing-key")),
        policy: engine,
        admin: sentin8::shield::admin::SharedAdminState::test("sentin8:storage", pool.clone()),
    };
    let router = routes(axum::Router::new()).with_state(state);
    Some((router, issuer, tmp, env_id))
}

/// Seed the enforced scope-mirror set (design §3.4 — the enroll path seeds
/// it per env in production; this fixture mirrors that). Permits grant each
/// storage action to holders of that same scope plus env/org-admin breadth,
/// exactly like the registered platform set.
fn seed_storage_scope_mirror(engine: &sentin8_storage_server::policy::Engine, env_id: &uuid::Uuid) {
    use sentin8::shield::{PolicyMode, PolicyOrigin, PolicySetRecord};
    // ONE set (UNIQUE key (env, service, policy_set_name) — separate upserts
    // with the same name would overwrite each other) containing ALL permits.
    let mut stmts: Vec<String> = Vec::new();
    for action in [
        "sentin8:storage:env:read",
        "sentin8:storage:env:write",
        "sentin8:storage:env:admin",
        "sentin8:storage:org:read",
        "sentin8:storage:org:write",
        "sentin8:storage:org:admin",
    ] {
        stmts.push(format!(
            "permit(principal, action == Action::\"{a}\", resource) when {{ principal.scopes.contains(\"{a}\") }};",
            a = action
        ));
        stmts.push(format!(
            "permit(principal, action == Action::\"{a}\", resource) when {{ principal.scopes.contains(\"sentin8:storage:env:admin\") }};",
            a = action
        ));
        stmts.push(format!(
            "permit(principal, action == Action::\"{a}\", resource) when {{ principal.scopes.contains(\"sentin8:storage:org:admin\") }};",
            a = action
        ));
    }
    engine
        .upsert(PolicySetRecord {
            id: uuid::Uuid::nil(),
            env_id: *env_id,
            service: "sentin8:storage".into(),
            policy_set_name: "scope-mirror".into(),
            description: String::new(),
            policies: stmts.join("\n"),
            schema: None,
            origin: PolicyOrigin::Platform,
            mode: PolicyMode::Enforced,
            version: 1,
            enabled: true,
        })
        .expect("seed storage scope-mirror set");
}

/// Persist the scope-mirror set row (`sys.policy_sets`) for the test env —
/// the durable half of [`seed_storage_scope_mirror`]. The engine's
/// sync-reload-on-empty-coverage path replaces the whole in-memory cache
/// from the DB, so a test-env set that exists only in memory is lost the
/// first time any other env (e.g. the unknown-env fixture) triggers a
/// reload. Production seeds the same row at enroll time.
async fn seed_storage_scope_mirror_row(pool: &sqlx::PgPool, env_id: &uuid::Uuid) {
    let mut stmts: Vec<String> = Vec::new();
    for action in [
        "sentin8:storage:env:read",
        "sentin8:storage:env:write",
        "sentin8:storage:env:admin",
        "sentin8:storage:org:read",
        "sentin8:storage:org:write",
        "sentin8:storage:org:admin",
    ] {
        stmts.push(format!(
            "permit(principal, action == Action::\"{a}\", resource) when {{ principal.scopes.contains(\"{a}\") }};",
            a = action
        ));
        stmts.push(format!(
            "permit(principal, action == Action::\"{a}\", resource) when {{ principal.scopes.contains(\"sentin8:storage:env:admin\") }};",
            a = action
        ));
        stmts.push(format!(
            "permit(principal, action == Action::\"{a}\", resource) when {{ principal.scopes.contains(\"sentin8:storage:org:admin\") }};",
            a = action
        ));
    }
    // SECURITY DEFINER boot-read path (same function production loads
    // through) — no tenant context is set in this fixture, so the direct
    // table insert must come from a role the function's owner can read
    // back; plain INSERT through the pooled dev role suffices.
    sqlx::query(
        r#"INSERT INTO sys.policy_sets
             (id, env_id, service, policy_set_name, description, policies,
              origin, mode, version, enabled)
           VALUES (gen_random_uuid(), $1, 'sentin8:storage', 'scope-mirror',
                   '', $2, 'platform', 'enforced', 1, true)
           ON CONFLICT (env_id, service, policy_set_name)
           DO UPDATE SET policies = EXCLUDED.policies, enabled = true,
                         version = sys.policy_sets.version + 1"#,
    )
    .bind(env_id)
    .bind(stmts.join("\n"))
    .execute(pool)
    .await
    .expect("persist storage scope-mirror set row");
}

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    String::from_utf8_lossy(&bytes).to_string()
}

// ── Scope matrix (design §6) ────────────────────────────────────────────

/// A token with no storage scope is rejected on every object route.
#[tokio::test]
async fn no_scope_rejected_on_all_object_routes() {
    let Some((app, issuer, _tmp, env)) = spawn_app().await else {
        return;
    };
    let tok = issuer.token(
        &format!("user-{}", uuid::Uuid::new_v4()),
        env.as_str(),
        "ledger:products:read",
        300,
    );
    for (method, uri) in [
        ("PUT", "/v1/storage/objects/x.txt"),
        ("GET", "/v1/storage/objects/x.txt"),
        ("DELETE", "/v1/storage/objects/x.txt"),
        ("GET", "/v1/storage/objects"),
        ("HEAD", "/v1/storage/objects/x.txt"),
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("authorization", format!("Bearer {tok}"))
                    .body(Body::from(b"data".to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "{method} {uri} must be 403 without a storage scope"
        );
    }
}

/// Read scope grants GET/HEAD/list but NOT delete (admin-only, design §6).
#[tokio::test]
async fn read_scope_cannot_delete() {
    let Some((app, issuer, _tmp, env)) = spawn_app().await else {
        return;
    };
    let tok = issuer.token(
        &format!("user-{}", uuid::Uuid::new_v4()),
        env.as_str(),
        "sentin8:storage:env:read",
        300,
    );
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/storage/objects/x.txt")
                .header("authorization", format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// Read scope does NOT grant upload (write scope required).
#[tokio::test]
async fn read_scope_cannot_put() {
    let Some((app, issuer, _tmp, env)) = spawn_app().await else {
        return;
    };
    let tok = issuer.token(
        &format!("user-{}", uuid::Uuid::new_v4()),
        env.as_str(),
        "sentin8:storage:env:read",
        300,
    );
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/storage/objects/x.txt")
                .header("authorization", format!("Bearer {tok}"))
                .body(Body::from(b"data".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// Write scope does NOT grant delete — admin scope required (§6).
#[tokio::test]
async fn write_scope_cannot_delete() {
    let Some((app, issuer, _tmp, env)) = spawn_app().await else {
        return;
    };
    let tok = issuer.token(
        &format!("user-{}", uuid::Uuid::new_v4()),
        env.as_str(),
        "sentin8:storage:env:write",
        300,
    );
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/storage/objects/x.txt")
                .header("authorization", format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// Write scope does NOT grant download — read scope required (§6).
#[tokio::test]
async fn write_scope_cannot_get() {
    let Some((app, issuer, _tmp, env)) = spawn_app().await else {
        return;
    };
    let tok = issuer.token(
        &format!("user-{}", uuid::Uuid::new_v4()),
        env.as_str(),
        "sentin8:storage:env:write",
        300,
    );
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/storage/objects/x.txt")
                .header("authorization", format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// Unauthenticated requests are rejected on protected routes.
#[tokio::test]
async fn unauthenticated_rejected() {
    let Some((app, _issuer, _tmp, _env)) = spawn_app().await else {
        return;
    };
    for (method, uri) in [
        ("GET", "/v1/storage/objects/x.txt"),
        ("PUT", "/v1/storage/objects/x.txt"),
        ("GET", "/v1/storage/objects"),
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{method} {uri}");
    }
}

/// `list_objects` propagates auth failures (401/403) instead of returning
/// an empty list (SEC-storage-6).
#[tokio::test]
async fn list_objects_propagates_auth_errors() {
    let Some((app, issuer, _tmp, env)) = spawn_app().await else {
        return;
    };
    let tok = issuer.token(
        &format!("user-{}", uuid::Uuid::new_v4()),
        env.as_str(),
        "no:relevant:scope",
        300,
    );
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/storage/objects")
                .header("authorization", format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_string(resp).await;
    assert!(
        !body.contains("\"objects\""),
        "auth failure must not be masked as an empty list: {body}"
    );
}

// ── Signed URLs (design §5.0a) ──────────────────────────────────────────

/// sign-read issues an HMAC token; a GET with it serves the object and a
/// forged token is rejected. (DB-backed: org resolution requires the env
/// row, so this runs against the real database.)
#[tokio::test]
async fn signed_read_roundtrip_and_forgery() {
    let Some((app, issuer, _tmp, env)) = spawn_app().await else {
        return;
    };
    let tok = issuer.token(
        &format!("user-{}", uuid::Uuid::new_v4()),
        env.as_str(),
        "sentin8:storage:env:read sentin8:storage:env:write sentin8:storage:env:admin",
        300,
    );
    let auth = ("authorization", format!("Bearer {tok}"));

    // Seed an object via the API.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/storage/objects/docs/signed.txt")
                .header(auth.0, auth.1.clone())
                .body(Body::from(b"signed payload".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "{}", body_string(resp).await);

    // Request a signed read URL.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/storage/objects/docs/signed.txt/sign-read")
                .header(auth.0, auth.1.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    let url = body["url"].as_str().unwrap().to_string();

    // GET the signed URL — serves the payload without auth.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(url.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_string(resp).await, "signed payload");

    // Tamper with the signature → 403 (not 200, not 404).
    let tampered = format!("{}x", &url[..url.len() - 1]);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(tampered)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        resp.status() == StatusCode::FORBIDDEN || resp.status() == StatusCode::BAD_REQUEST,
        "forged token must be rejected, got {}",
        resp.status()
    );
}

/// An unsigned legacy token (`base64(key|expiry)`) must NOT be accepted.
#[tokio::test]
async fn unsigned_legacy_token_rejected() {
    let Some((app, _issuer, _tmp, _env)) = spawn_app().await else {
        return;
    };
    use base64::Engine;
    let legacy = format!(
        "/v1/storage/signed/{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!(
            "org/o/env/e/file.txt|{}",
            chrono::Utc::now().timestamp() + 3600
        ))
    );
    let resp = app
        .clone()
        .oneshot(Request::builder().uri(legacy).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "unsigned token must not serve data"
    );
    assert!(
        resp.status() == StatusCode::BAD_REQUEST || resp.status() == StatusCode::FORBIDDEN,
        "got {}",
        resp.status()
    );
}

/// Expired signed tokens are rejected with 403.
#[tokio::test]
async fn expired_signed_token_rejected() {
    let codec = SignedUrlCodec::new(b"test-signing-key");
    let tok = codec.issue("org/o/env/e/f.txt", -1, SignedMethod::Get);
    let Some((app, _issuer, _tmp, _env)) = spawn_app().await else {
        return;
    };
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/storage/signed/{tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// A signed upload token works via PUT and is rejected for GET.
#[tokio::test]
async fn signed_upload_method_enforced() {
    let Some((app, issuer, _tmp, env)) = spawn_app().await else {
        return;
    };
    let tok = issuer.token(
        &format!("user-{}", uuid::Uuid::new_v4()),
        env.as_str(),
        "sentin8:storage:env:read sentin8:storage:env:write",
        300,
    );
    let auth = ("authorization", format!("Bearer {tok}"));

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/storage/objects/uploads/signed.bin/sign-upload")
                .header(auth.0, auth.1.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "{}", body_string(resp).await);
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    let url = body["url"].as_str().unwrap().to_string();

    // GET with an upload token → 405 (method not authorized).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(url.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);

    // PUT with the upload token → stores the object.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(url)
                .body(Body::from(b"uploaded via signed url".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "{}", body_string(resp).await);

    // Read back with the owner token.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/storage/objects/uploads/signed.bin")
                .header(auth.0, auth.1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_string(resp).await, "uploaded via signed url");
}

/// A read token is rejected for PUT.
#[tokio::test]
async fn signed_read_token_rejected_for_put() {
    let Some((app, issuer, _tmp, env)) = spawn_app().await else {
        return;
    };
    let tok = issuer.token(
        &format!("user-{}", uuid::Uuid::new_v4()),
        env.as_str(),
        "sentin8:storage:env:read sentin8:storage:env:write",
        300,
    );
    let auth = ("authorization", format!("Bearer {tok}"));
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/storage/objects/uploads/x.bin/sign-read")
                .header(auth.0, auth.1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
    let url = body["url"].as_str().unwrap().to_string();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(url)
                .body(Body::from(b"nope".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

// ── Dedup / HEAD (platform story 0.2) ───────────────────────────────────

/// put-if-absent short-circuits on an existing object and reports the
/// dedup marker; a plain PUT overwrites.
#[tokio::test]
async fn put_if_absent_dedup_headers() {
    let Some((app, issuer, _tmp, env)) = spawn_app().await else {
        return;
    };
    let tok = issuer.token(
        &format!("user-{}", uuid::Uuid::new_v4()),
        env.as_str(),
        "sentin8:storage:env:read sentin8:storage:env:write",
        300,
    );
    let auth = ("authorization", format!("Bearer {tok}"));
    let uri = "/v1/storage/objects/ca/abc123";

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(uri)
                .header(auth.0, auth.1.clone())
                .body(Body::from(b"first".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Dedup PUT → 200 with the marker, original content preserved.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(uri)
                .header(auth.0, auth.1.clone())
                .header("x-if-absent", "true")
                .body(Body::from(b"second".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-storage-deduped")
            .and_then(|v| v.to_str().ok()),
        Some("true")
    );
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(auth.0, auth.1.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(body_string(resp).await, "first");

    // Plain PUT → overwrite.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(uri)
                .header(auth.0, auth.1.clone())
                .body(Body::from(b"second".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(auth.0, auth.1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(body_string(resp).await, "second");
}

/// HEAD returns Content-Length and 404 for missing objects.
#[tokio::test]
async fn head_probe() {
    let Some((app, issuer, _tmp, env)) = spawn_app().await else {
        return;
    };
    let tok = issuer.token(
        &format!("user-{}", uuid::Uuid::new_v4()),
        env.as_str(),
        "sentin8:storage:env:read sentin8:storage:env:write",
        300,
    );
    let auth = ("authorization", format!("Bearer {tok}"));

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/storage/objects/probe.bin")
                .header(auth.0, auth.1.clone())
                .body(Body::from(vec![0u8; 42]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/v1/storage/objects/probe.bin")
                .header(auth.0, auth.1.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok()),
        Some("42")
    );

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/v1/storage/objects/missing.bin")
                .header(auth.0, auth.1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── Public read ─────────────────────────────────────────────────────────

/// Public read serves only image extensions and sets content headers.
#[tokio::test]
async fn public_read_extension_filter() {
    let Some((app, _issuer, _tmp, _env)) = spawn_app().await else {
        return;
    };
    // Non-image extension → 403, regardless of existence/auth.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/public/objects/secret.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Image extension but missing object → 404 (not 403).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/public/objects/missing-logo.png")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── Adapter-level security (traversal, isolation) ────────────────────────

/// PUT with traversal components must be rejected by the adapter — the
/// file must never land outside the root (SEC-storage-2).
#[tokio::test]
async fn adapter_put_traversal_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let adapter = LocalFsAdapter::new(tmp.path());
    let root = tmp.path().to_string_lossy().to_string();

    for key in [
        "org/o/env/e/../../escape.txt",
        "../../escape.txt",
        "a/../../escape.txt",
    ] {
        let err = adapter
            .put(key, b"evil".to_vec(), "text/plain")
            .await
            .expect_err("traversal put must fail");
        assert!(
            matches!(
                err,
                sentin8_storage_server::storage::StorageError::PathTraversal(_)
            ),
            "{key}: {err:?}"
        );
    }
    // Nothing was written outside the root.
    let escaped = std::path::Path::new(&root)
        .parent()
        .unwrap()
        .join("escape.txt");
    assert!(!escaped.exists(), "file escaped the storage root");
}

/// A symlink pointing outside the root is not followed on write.
#[tokio::test]
async fn adapter_symlink_escape_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let adapter = LocalFsAdapter::new(tmp.path());
    std::fs::create_dir_all(tmp.path().join("org/o/env/e")).unwrap();
    std::os::unix::fs::symlink(outside.path(), tmp.path().join("org/o/env/e/link")).unwrap();
    let err = adapter
        .put("org/o/env/e/link/evil.txt", b"x".to_vec(), "text/plain")
        .await
        .expect_err("symlink escape must fail");
    assert!(
        matches!(
            err,
            sentin8_storage_server::storage::StorageError::PathTraversal(_)
        ),
        "{err:?}"
    );
}

/// The HMAC codec round-trips and rejects tampering (unit-level).
#[test]
fn signed_codec_unit() {
    let codec = SignedUrlCodec::new(b"k");
    let t = codec.issue("a/b", 60, SignedMethod::Get);
    assert_eq!(codec.verify(&t).unwrap().0, "a/b");
    // Tampered payload rejected.
    let (payload, sig) = t.rsplit_once('.').unwrap();
    let tampered = format!("{payload}X.{sig}");
    assert!(codec.verify(&tampered).is_err());
    // Different key rejected.
    assert!(SignedUrlCodec::new(b"other").verify(&t).is_err());
}
