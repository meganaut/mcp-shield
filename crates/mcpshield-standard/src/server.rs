use std::sync::Arc;

use anyhow::{Context, Result};
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, post};
use tokio::net::TcpListener;

use crate::admin::{delete_policy, get_policy, list_agents, set_policy};
use crate::config::Config;
use crate::crypto::unix_timestamp_secs;
use crate::downstream::DownstreamClient;
use crate::handler::{
    mcp_handler_authenticated, new_pending_store, new_rate_limiter, new_setup_csrf_token, AppState,
};
use crate::noop::NoopAudit;
use crate::oauth::authorize::{get_authorize, post_authorize};
use crate::oauth::dcr::post_register;
use crate::oauth::metadata::get_metadata;
use crate::oauth::token::post_token;
use crate::session::new_store;
use crate::setup::{get_setup, get_setup_done, post_setup};
use mcpshield_db::Store;
use mcpshield_db_sqlite::SqliteStore;
use mcpshield_policy_db::DbPolicyEngine;

pub async fn run(config: Config) -> Result<()> {
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

    let addr = format!("{}:{}", config.server.listen_addr, config.server.port);

    if !db.is_setup_complete().await.context("check setup")? {
        tracing::info!("Setup not complete — serving setup wizard on http://{addr}/setup");

        // Build a minimal state for the setup wizard
        // We still need a full AppState but with a stub downstream
        let downstream = Arc::new(DownstreamClient::new(
            "http://localhost:1".to_string(),
            "setup".to_string(),
        ));

        let state = Arc::new(AppState {
            sessions: new_store(),
            downstream,
            policy: Arc::new(DbPolicyEngine::new(Arc::clone(&db))),
            audit: Arc::new(NoopAudit),
            db: Arc::clone(&db),
            pending_auth: new_pending_store(),
            rate_limiter: new_rate_limiter(),
            setup_csrf_token: new_setup_csrf_token(),
        });

        let app = Router::new()
            .route("/setup", get(get_setup).post(post_setup))
            .route("/setup/done", get(get_setup_done))
            .layer(DefaultBodyLimit::max(64 * 1024))
            .with_state(state);

        return run_plain(app, &addr).await;
    }

    // Full gateway mode
    let downstream = Arc::new(DownstreamClient::new(
        config.downstream.url.clone(),
        config.downstream.slug.clone(),
    ));

    downstream
        .initialize()
        .await
        .context("failed to initialize downstream connection")?;

    let state = Arc::new(AppState {
        sessions: new_store(),
        downstream,
        policy: Arc::new(DbPolicyEngine::new(Arc::clone(&db))),
        audit: Arc::new(NoopAudit),
        db: Arc::clone(&db),
        pending_auth: new_pending_store(),
        rate_limiter: new_rate_limiter(),
        setup_csrf_token: new_setup_csrf_token(),
    });

    // Spawn cleanup task — runs immediately on startup, then every 5 minutes
    let cleanup_db = Arc::clone(&db);
    tokio::spawn(async move {
        loop {
            let now = unix_timestamp_secs();
            if let Err(e) = cleanup_db.delete_expired_access_tokens(now).await {
                tracing::warn!(err = %e, "cleanup: failed to delete expired access_tokens");
            }
            if let Err(e) = cleanup_db.delete_expired_auth_codes(now).await {
                tracing::warn!(err = %e, "cleanup: failed to delete expired auth_codes");
            }
            tokio::time::sleep(std::time::Duration::from_secs(300)).await;
        }
    });

    let app = Router::new()
        // MCP proxy (authenticated)
        .route("/mcp", post(mcp_handler_authenticated))
        // OAuth endpoints
        .route("/.well-known/oauth-authorization-server", get(get_metadata))
        .route("/oauth/register", post(post_register))
        .route("/oauth/authorize", get(get_authorize).post(post_authorize))
        .route("/oauth/token", post(post_token))
        // Admin endpoints
        .route("/admin/agents", get(list_agents))
        .route("/admin/agents/{agent_id}/policy", get(get_policy).post(set_policy))
        .route("/admin/agents/{agent_id}/policy/{tool_name}", delete(delete_policy))
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
    axum::serve(listener, app).await.context("server error")
}

#[cfg(feature = "tls")]
async fn run_tls(app: Router, addr: &str, config: &Config) -> Result<()> {
    use tokio_rustls::rustls::ServerConfig;
    use tokio_rustls::TlsAcceptor;
    use hyper::server::conn::http1;
    use hyper_util::rt::TokioIo;
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
        let (stream, _peer_addr) = listener.accept().await.context("accept connection")?;
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
                    hyper::service::service_fn(move |req| {
                        let mut svc = app.clone();
                        async move { svc.call(req).await }
                    }),
                )
                .await;
        });
    }
}
