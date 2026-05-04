use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, post};
use dashmap::DashMap;
use tokio::net::TcpListener;

use crate::admin::{
    assign_agent_profile, connect_authorize, connect_client_credentials, create_integration,
    create_profile, delete_agent, delete_agent_override_handler, delete_global_rule_handler,
    delete_integration_handler, delete_policy, delete_profile_handler, delete_profile_rule_handler,
    get_policy, get_profile, integration_oauth_callback, list_agent_overrides_handler,
    list_agents, list_global_rules_handler, list_integrations, list_profile_rules_handler,
    list_profiles, refresh_integration, revoke_agent_tokens, set_agent_override, set_global_rule,
    set_policy, set_profile_rule, set_profile_rules_bulk, update_profile,
};
use crate::audit::DbAuditSink;
use crate::config::Config;
use crate::crypto::unix_timestamp_secs;
use crate::downstream::DownstreamClient;
use crate::handler::{
    mcp_handler_authenticated, new_admin_session_key, new_pending_store,
    new_pending_integration_auth_store, new_rate_limiter, new_setup_csrf_token, AppState,
    PENDING_AUTH_TTL_SECS, PENDING_INTEGRATION_TTL_SECS,
};
use crate::ui::{
    get_ui_agent_detail, get_ui_agents, get_ui_audit, get_ui_dashboard,
    get_ui_integration_tools, get_ui_integrations, get_ui_login, get_ui_profile_detail,
    get_ui_profiles, post_ui_create_profile, post_ui_login, post_ui_logout,
    post_ui_rename_profile,
};
use crate::oauth::authorize::{get_authorize, post_authorize};
use crate::oauth::dcr::post_register;
use crate::oauth::metadata::get_metadata;
use crate::oauth::token::post_token;
use crate::policy_cache::CachingPolicyEngine;
use crate::session::new_store;
use crate::setup::{get_setup, get_setup_done, post_setup};
use crate::vault::{load_or_create_vault_key, SqliteVaultBackend};
use mcpcondor_core::vault::VaultBackend;
use mcpcondor_db::Store;
use mcpcondor_db_sqlite::SqliteStore;
use mcpcondor_policy_db::DbPolicyEngine;

pub async fn run(config: Config) -> Result<()> {
    tokio::fs::create_dir_all(&config.server.data_dir)
        .await
        .context("create data directory")?;

    let db_path = config
        .server
        .data_dir
        .join("mcpcondor.db")
        .to_string_lossy()
        .into_owned();

    let store = SqliteStore::open(&db_path)
        .await
        .context("open database")?;
    store.run_migrations().await.context("run migrations")?;
    let db: Arc<dyn Store> = Arc::new(store);

    let vault_key = load_or_create_vault_key(&config.server.data_dir)
        .context("load or create vault key")?;
    let vault: Arc<dyn VaultBackend> = Arc::new(SqliteVaultBackend::new(Arc::clone(&db), vault_key));

    let addr = format!("{}:{}", config.server.listen_addr, config.server.port);

    if !db.is_setup_complete().await.context("check setup")? {
        tracing::info!("Setup not complete — visit http://{addr}/setup to configure MCPCondor");
    }

    // Load all integrations from DB
    let downstreams: Arc<DashMap<String, Arc<DownstreamClient>>> = Arc::new(DashMap::new());

    let integrations = db.list_integrations().await.context("load integrations")?;
    for integration in integrations {
        match DownstreamClient::new(
            integration.mcp_url.clone(),
            integration.slug.clone(),
            integration.id.clone(),
        ) {
            Ok(client) => {
                let client = Arc::new(client);
                downstreams.insert(integration.slug.clone(), Arc::clone(&client));

                // Try to initialize at startup — non-fatal on failure
                if integration.connected {
                    let client_clone = Arc::clone(&client);
                    let vault_clone = Arc::clone(&vault);
                    let integration_id = integration.id.clone();
                    tokio::spawn(async move {
                        let auth_token = match vault_clone.get_token(&integration_id).await {
                            Ok(Some(data)) => data.access_token,
                            _ => None,
                        };
                        if let Err(e) = client_clone.initialize(auth_token.as_deref()).await {
                            tracing::warn!(
                                err = %e,
                                slug = %client_clone.slug(),
                                "downstream not reachable at startup"
                            );
                        }
                    });
                }
            }
            Err(e) => {
                tracing::warn!(
                    err = %e,
                    slug = %integration.slug,
                    "failed to build downstream client for integration"
                );
            }
        }
    }

    let policy = Arc::new(CachingPolicyEngine::new(Arc::new(
        DbPolicyEngine::new(Arc::clone(&db)),
    )));

    let state = Arc::new(AppState {
        sessions: new_store(),
        downstreams,
        policy,
        audit: Arc::new(DbAuditSink::new(Arc::clone(&db))),
        db: Arc::clone(&db),
        vault,
        pending_auth: new_pending_store(),
        pending_integration_auth: new_pending_integration_auth_store(),
        rate_limiter: new_rate_limiter(),
        admin_rate_limiter: new_rate_limiter(),
        setup_csrf_token: new_setup_csrf_token(),
        admin_session_key: new_admin_session_key(),
        bearer_cache: Arc::new(DashMap::new()),
        vault_cache: Arc::new(DashMap::new()),
    });

    let cleanup_state = Arc::clone(&state);
    let audit_retention_days = config.server.audit_retention_days;
    tokio::spawn(async move {
        loop {
            let now = unix_timestamp_secs();

            // DB — expire tokens and auth codes
            if let Err(e) = cleanup_state.db.delete_expired_access_tokens(now).await {
                tracing::warn!(err = %e, "cleanup: failed to delete expired access_tokens");
            }
            if let Err(e) = cleanup_state.db.delete_expired_auth_codes(now).await {
                tracing::warn!(err = %e, "cleanup: failed to delete expired auth_codes");
            }

            // Audit retention — delete events older than configured retention window
            let retention_ms = (audit_retention_days as i64) * 86_400 * 1_000;
            let cutoff_ms = now * 1_000 - retention_ms;
            if let Err(e) = cleanup_state.db.delete_old_audit_events(cutoff_ms).await {
                tracing::warn!(err = %e, "cleanup: failed to delete old audit events");
            }

            // In-memory caches — evict stale entries so memory stays bounded
            cleanup_state.bearer_cache.retain(|_, (_, _, expiry)| now < *expiry);
            cleanup_state.vault_cache.retain(|_, (_, cached_at)| cached_at.elapsed().as_secs() < 5);
            cleanup_state.pending_auth.retain(|_, v| now - v.created_at < PENDING_AUTH_TTL_SECS);
            cleanup_state.pending_integration_auth.retain(|_, v| now - v.created_at < PENDING_INTEGRATION_TTL_SECS);

            tokio::time::sleep(std::time::Duration::from_secs(300)).await;
        }
    });

    let app = Router::new()
        // Root redirect
        .route("/", get(root_redirect))
        // Setup wizard
        .route("/setup", get(get_setup).post(post_setup))
        .route("/setup/done", get(get_setup_done))
        // Admin UI
        .route("/ui", get(get_ui_dashboard))
        .route("/ui/login", get(get_ui_login).post(post_ui_login))
        .route("/ui/logout", post(post_ui_logout))
        .route("/ui/integrations", get(get_ui_integrations))
        .route("/ui/integrations/{id}/tools", get(get_ui_integration_tools))
        .route("/ui/agents", get(get_ui_agents))
        .route("/ui/agents/{id}", get(get_ui_agent_detail))
        .route("/ui/profiles", get(get_ui_profiles).post(post_ui_create_profile))
        .route("/ui/profiles/{id}", get(get_ui_profile_detail))
        .route("/ui/profiles/{id}/rename", post(post_ui_rename_profile))
        .route("/ui/audit", get(get_ui_audit))
        // Static assets for the UI
        .route("/assets/{*path}", get(ui_assets))
        // MCP gateway
        .route("/mcp", post(mcp_handler_authenticated))
        .route("/.well-known/oauth-authorization-server", get(get_metadata))
        .route("/oauth/register", post(post_register))
        .route("/oauth/authorize", get(get_authorize).post(post_authorize))
        .route("/oauth/token", post(post_token))
        .route("/oauth/integrations/{id}/callback", get(integration_oauth_callback))
        .route("/admin/agents", get(list_agents))
        .route("/admin/agents/{agent_id}", delete(delete_agent))
        .route("/admin/agents/{agent_id}/tokens", delete(revoke_agent_tokens))
        .route("/admin/agents/{agent_id}/policy", get(get_policy).post(set_policy))
        .route("/admin/agents/{agent_id}/policy/{tool_name}", delete(delete_policy))
        .route("/admin/agents/{agent_id}/overrides", get(list_agent_overrides_handler).post(set_agent_override))
        .route("/admin/agents/{agent_id}/overrides/{tool_name}", delete(delete_agent_override_handler))
        .route("/admin/agents/{agent_id}/profile", post(assign_agent_profile))
        .route("/admin/profiles", get(list_profiles).post(create_profile))
        .route("/admin/profiles/{id}", get(get_profile).put(update_profile).delete(delete_profile_handler))
        .route("/admin/profiles/{id}/rules", get(list_profile_rules_handler).post(set_profile_rule))
        .route("/admin/profiles/{id}/rules/bulk", post(set_profile_rules_bulk))
        .route("/admin/profiles/{id}/rules/{tool_name}", delete(delete_profile_rule_handler))
        .route("/admin/global-rules", get(list_global_rules_handler).post(set_global_rule))
        .route("/admin/global-rules/{tool_name}", delete(delete_global_rule_handler))
        .route("/admin/integrations", get(list_integrations).post(create_integration))
        .route("/admin/integrations/{id}", delete(delete_integration_handler))
        .route("/admin/integrations/{id}/refresh", post(refresh_integration))
        .route("/admin/integrations/{id}/connect/client-credentials", post(connect_client_credentials))
        .route("/admin/integrations/{id}/connect/authorize", post(connect_authorize))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(state);

    let addr_str = addr.as_str();

    #[cfg(feature = "tls")]
    {
        run_tls(app, addr_str, &config).await
    }

    #[cfg(not(feature = "tls"))]
    {
        run_plain(app, addr_str).await
    }
}

async fn ui_assets(
    axum::extract::Path(path): axum::extract::Path<String>,
) -> axum::response::Response {
    use axum::http::{header, StatusCode};
    use axum::response::IntoResponse;
    match mcpcondor_ui::assets::StaticAssets::get(&path) {
        Some(content) => {
            let mime = match path.rsplit('.').next().unwrap_or("") {
                "css" => "text/css",
                "js" => "application/javascript",
                "svg" => "image/svg+xml",
                "png" => "image/png",
                "ico" => "image/x-icon",
                _ => "application/octet-stream",
            };
            ([(header::CONTENT_TYPE, mime)], content.data.into_owned()).into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn root_redirect(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> axum::response::Response {
    use axum::response::{IntoResponse, Redirect};
    match state.db.is_setup_complete().await {
        Ok(true) => Redirect::to("/ui").into_response(),
        _ => Redirect::to("/setup").into_response(),
    }
}

async fn run_plain(app: Router, addr: &str) -> Result<()> {
    tracing::info!("listening on http://{addr}");
    let listener = TcpListener::bind(addr)
        .await
        .context("bind listener")?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("server error")
}

#[cfg(feature = "tls")]
async fn run_tls(app: Router, addr: &str, config: &Config) -> Result<()> {
    use axum::extract::ConnectInfo;
    use hyper::server::conn::http1;
    use hyper_util::rt::TokioIo;
    use tokio_rustls::rustls::ServerConfig;
    use tokio_rustls::TlsAcceptor;
    use tower::Service;

    let tls_material = crate::tls::load_or_generate(&config.server.data_dir)
        .context("TLS cert load/generate")?;

    let tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(tls_material.cert_der, tls_material.key_der)
        .context("configure TLS")?;

    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let listener = TcpListener::bind(addr)
        .await
        .context("bind TLS listener")?;

    tracing::info!("listening on https://{addr}");

    loop {
        let (stream, peer_addr) = listener.accept().await.context("accept connection")?;
        let acceptor = acceptor.clone();
        let app = app.clone();

        tokio::spawn(async move {
            let Ok(tls_stream) = acceptor.accept(stream).await else {
                return;
            };
            let io = TokioIo::new(tls_stream);
            let _ = http1::Builder::new()
                .serve_connection(
                    io,
                    hyper::service::service_fn(move |mut req| {
                        req.extensions_mut().insert(ConnectInfo(peer_addr));
                        let mut svc = app.clone();
                        async move { svc.call(req).await }
                    }),
                )
                .await;
        });
    }
}
