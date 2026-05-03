use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, post};
use dashmap::DashMap;
use tokio::net::TcpListener;

use crate::admin::{
    connect_authorize, connect_client_credentials, create_integration, delete_agent,
    delete_integration_handler, delete_policy, get_policy, integration_oauth_callback,
    list_agents, list_integrations, refresh_integration, revoke_agent_tokens, set_policy,
};
use crate::audit::DbAuditSink;
use crate::config::Config;
use crate::crypto::unix_timestamp_secs;
use crate::downstream::DownstreamClient;
use crate::handler::{
    mcp_handler_authenticated, new_pending_store, new_pending_integration_auth_store,
    new_rate_limiter, new_setup_csrf_token, AppState, PENDING_AUTH_TTL_SECS,
    PENDING_INTEGRATION_TTL_SECS,
};
use crate::oauth::authorize::{get_authorize, post_authorize};
use crate::oauth::dcr::post_register;
use crate::oauth::metadata::get_metadata;
use crate::oauth::token::post_token;
use crate::policy_cache::CachingPolicyEngine;
use crate::session::new_store;
use crate::setup::{get_setup, get_setup_done, post_setup};
use crate::vault::{load_or_create_vault_key, SqliteVaultBackend};
use mcpshield_core::vault::VaultBackend;
use mcpshield_db::Store;
use mcpshield_db_sqlite::SqliteStore;
use mcpshield_policy_db::DbPolicyEngine;

pub async fn run(config: Config) -> Result<()> {
    tokio::fs::create_dir_all(&config.server.data_dir)
        .await
        .context("create data directory")?;

    let db_path = config
        .server
        .data_dir
        .join("mcpshield.db")
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
        tracing::info!("Setup not complete — serving setup wizard on http://{addr}/setup");

        let policy = Arc::new(CachingPolicyEngine::new(Arc::new(
            DbPolicyEngine::new(Arc::clone(&db)),
        )));

        let state = Arc::new(AppState {
            sessions: new_store(),
            downstreams: Arc::new(DashMap::new()),
            policy,
            audit: Arc::new(DbAuditSink::new(Arc::clone(&db))),
            db: Arc::clone(&db),
            vault,
            pending_auth: new_pending_store(),
            pending_integration_auth: new_pending_integration_auth_store(),
            rate_limiter: new_rate_limiter(),
            admin_rate_limiter: new_rate_limiter(),
            setup_csrf_token: new_setup_csrf_token(),
            bearer_cache: Arc::new(DashMap::new()),
            vault_cache: Arc::new(DashMap::new()),
        });

        let app = Router::new()
            .route("/setup", get(get_setup).post(post_setup))
            .route("/setup/done", get(get_setup_done))
            .layer(DefaultBodyLimit::max(64 * 1024))
            .with_state(state);

        return run_plain(app, &addr).await;
    }

    // Full gateway mode — load all integrations from DB
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
        bearer_cache: Arc::new(DashMap::new()),
        vault_cache: Arc::new(DashMap::new()),
    });

    let cleanup_state = Arc::clone(&state);
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

            // In-memory caches — evict stale entries so memory stays bounded
            cleanup_state.bearer_cache.retain(|_, (_, _, expiry)| now < *expiry);
            cleanup_state.vault_cache.retain(|_, (_, cached_at)| cached_at.elapsed().as_secs() < 5);
            cleanup_state.pending_auth.retain(|_, v| now - v.created_at < PENDING_AUTH_TTL_SECS);
            cleanup_state.pending_integration_auth.retain(|_, v| now - v.created_at < PENDING_INTEGRATION_TTL_SECS);

            tokio::time::sleep(std::time::Duration::from_secs(300)).await;
        }
    });

    let app = Router::new()
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
