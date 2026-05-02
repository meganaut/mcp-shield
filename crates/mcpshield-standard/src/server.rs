use std::sync::Arc;

use anyhow::{Context, Result};
use axum::Router;
use axum::routing::post;
use tokio::net::TcpListener;

use crate::config::Config;
use crate::downstream::DownstreamClient;
use crate::handler::{mcp_handler, AppState};
use crate::noop::{NoopAudit, NoopPolicy};
use crate::session::new_store;

pub async fn run(config: Config) -> Result<()> {
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
        policy: Arc::new(NoopPolicy),
        audit: Arc::new(NoopAudit),
    });

    let app = Router::new()
        .route("/mcp", post(mcp_handler))
        .with_state(state);

    let addr = format!("{}:{}", config.server.listen_addr, config.server.port);

    #[cfg(feature = "tls")]
    {
        run_tls(app, &addr, &config).await
    }

    #[cfg(not(feature = "tls"))]
    {
        run_plain(app, &addr).await
    }
}

#[cfg(not(feature = "tls"))]
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
