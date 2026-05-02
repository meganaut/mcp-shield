// GET /.well-known/oauth-authorization-server

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::handler::AppState;

pub async fn get_metadata(State(state): State<Arc<AppState>>) -> Response {
    let issuer_url = match state.db.get_setup_value("issuer_url").await {
        Ok(Some(url)) => url,
        Ok(None) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "issuer_url not configured",
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(err = %e, "metadata: db error fetching issuer_url");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response();
        }
    };

    let metadata = json!({
        "issuer": issuer_url,
        "authorization_endpoint": format!("{}/oauth/authorize", issuer_url),
        "token_endpoint": format!("{}/oauth/token", issuer_url),
        "registration_endpoint": format!("{}/oauth/register", issuer_url),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"]
    });

    axum::http::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("cache-control", "max-age=3600")
        .body(axum::body::Body::from(
            serde_json::to_string(&metadata).expect("metadata is always serialisable"),
        ))
        .expect("valid response headers")
}
