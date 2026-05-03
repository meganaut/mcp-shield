// GET  /oauth/authorize  — render login form
// POST /oauth/authorize  — verify credentials, issue auth code

use std::sync::Arc;

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::Form;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use mcpshield_db::AuthCode;

use crate::crypto::{random_base64url, unix_timestamp_secs};
use crate::handler::{extract_client_ip, AppState, PeerIp, PendingAuthRequest};

fn make_csp(_issuer_url: &str) -> String {
    // form-action intentionally omitted: default-src 'none' prevents all script execution,
    // so there is no XSS vector to hijack the form action. The request_id provides CSRF protection.
    "default-src 'none'; style-src 'unsafe-inline'".to_string()
}

const PENDING_TTL_SECS: i64 = 600; // 10 minutes
const MAX_PENDING_ENTRIES: usize = 10_000;
/// Argon2 long-input DoS cap — no legitimate credential exceeds 1 KiB
const MAX_PASSWORD_BYTES: usize = 1024;
/// OAuth `state` parameter length cap — prevents large in-memory entries
const MAX_STATE_BYTES: usize = 1024;

/// S256 code_challenge is always base64url(SHA-256(verifier)) = 43 bytes
const CODE_CHALLENGE_LEN: usize = 43;
/// Abort an OAuth flow after this many consecutive credential failures.
const MAX_AUTH_ATTEMPTS: u8 = 5;

static LOGIN_FORM: &str = r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>MCPShield — Authorize</title>
<style>
  body { font-family: sans-serif; max-width: 400px; margin: 60px auto; padding: 0 1rem; }
  label { display: block; margin-top: 1rem; font-weight: bold; }
  input[type=text], input[type=password] { width: 100%; padding: .5rem; margin-top: .25rem; box-sizing: border-box; }
  .error { color: red; margin-top: .75rem; }
  button { margin-top: 1.5rem; padding: .6rem 1.5rem; background: #0066cc; color: white; border: none; cursor: pointer; font-size: 1rem; }
</style>
</head>
<body>
<h1>Authorize Agent</h1>
<p>Sign in to authorize <strong>{CLIENT_NAME}</strong>.</p>
{ERROR}
<form method="POST" action="{ACTION_URL}">
  <input type="hidden" name="request_id" value="{REQUEST_ID}">
  <label>Username<input type="text" name="username" autocomplete="username"></label>
  <label>Password<input type="password" name="password" autocomplete="current-password"></label>
  <button type="submit">Sign in &amp; Authorize</button>
</form>
</body>
</html>"#;

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub state: Option<String>,
}

pub async fn get_authorize(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AuthorizeQuery>,
) -> Response {
    let client_id = match &query.client_id {
        Some(id) if !id.is_empty() => id.clone(),
        _ => {
            return (StatusCode::BAD_REQUEST, "invalid_client").into_response();
        }
    };

    // Look up client — do NOT redirect on unknown client_id (open redirect prevention)
    let client_info = match state.db.get_client_authorize_info(&client_id).await {
        Ok(Some(info)) => info,
        Ok(None) => {
            return (StatusCode::BAD_REQUEST, "invalid_client").into_response();
        }
        Err(e) => {
            tracing::error!(err = %e, "authorize: db error looking up client");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response();
        }
    };

    let agent_id = client_info.agent_id;
    let stored_redirect_uris = client_info.redirect_uris;
    let client_name = client_info.client_name;

    // Validate redirect_uri before redirecting — do NOT redirect on bad redirect_uri
    let redirect_uri = match &query.redirect_uri {
        Some(u) if !u.is_empty() => u.clone(),
        _ => {
            return (StatusCode::BAD_REQUEST, "invalid_redirect_uri").into_response();
        }
    };

    if !stored_redirect_uris.contains(&redirect_uri) {
        return (StatusCode::BAD_REQUEST, "invalid_redirect_uri").into_response();
    }

    // From here on, redirect errors back to the client
    let response_type = query.response_type.as_deref().unwrap_or("");
    if response_type != "code" {
        return redirect_with_error(&redirect_uri, "unsupported_response_type", query.state.as_deref());
    }

    let method = query.code_challenge_method.as_deref().unwrap_or("");
    if method != "S256" {
        return redirect_with_error(&redirect_uri, "invalid_request", query.state.as_deref());
    }

    // Validate code_challenge using byte lengths for consistency — S256 output is always 43 ASCII bytes.
    let code_challenge = match &query.code_challenge {
        Some(c)
            if c.len() == CODE_CHALLENGE_LEN
                && c.bytes().all(|b| {
                    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_')
                }) =>
        {
            c.clone()
        }
        _ => {
            return redirect_with_error(&redirect_uri, "invalid_request", query.state.as_deref());
        }
    };

    let state_param = match &query.state {
        Some(s) if s.len() > MAX_STATE_BYTES => {
            return redirect_with_error(&redirect_uri, "invalid_request", None);
        }
        Some(s) => s.clone(),
        None => String::new(),
    };

    let request_id = random_base64url(16);
    let now = unix_timestamp_secs();

    // Purge stale entries then enforce the cap. The retain+len+insert is not atomic
    // under concurrent requests, so the effective max is MAX_PENDING_ENTRIES + concurrent_tasks.
    // This is acceptable given the 10-minute TTL and the benign nature of the overshoot.
    state.pending_auth.retain(|_, v| now - v.created_at < PENDING_TTL_SECS);
    if state.pending_auth.len() >= MAX_PENDING_ENTRIES {
        return redirect_with_error(&redirect_uri, "temporarily_unavailable", Some(&state_param));
    }

    state.pending_auth.insert(
        request_id.clone(),
        PendingAuthRequest {
            client_id,
            redirect_uri,
            code_challenge,
            state: state_param,
            agent_id,
            created_at: now,
            attempts: 0,
        },
    );

    let issuer = match state.db.get_setup_value("issuer_url").await {
        Ok(Some(u)) => u,
        _ => String::new(),
    };
    let action_url = format!("{}/oauth/authorize", issuer.trim_end_matches('/'));

    let html = LOGIN_FORM
        .replace("{CLIENT_NAME}", &html_escape(&client_name))
        .replace("{REQUEST_ID}", &html_escape(&request_id))
        .replace("{ACTION_URL}", &html_escape(&action_url))
        .replace("{ERROR}", "");

    axum::http::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .header("content-security-policy", make_csp(&issuer))
        .header("x-frame-options", "DENY")
        .header("referrer-policy", "no-referrer")
        .body(axum::body::Body::from(html))
        .expect("valid response headers")
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeForm {
    pub request_id: String,
    pub username: String,
    pub password: String,
}

pub async fn post_authorize(
    State(state): State<Arc<AppState>>,
    _headers: axum::http::HeaderMap,
    PeerIp(peer_ip): PeerIp,
    Form(form): Form<AuthorizeForm>,
) -> Response {
    let now = unix_timestamp_secs();
    let ip = extract_client_ip(peer_ip);

    if !state.rate_limiter.allow(&ip, now) {
        return (StatusCode::TOO_MANY_REQUESTS, "Too many requests").into_response();
    }

    let pending = match state.pending_auth.remove(&form.request_id) {
        Some((_, p)) if now - p.created_at < PENDING_TTL_SECS => p,
        Some(_) | None => {
            return (StatusCode::BAD_REQUEST, "invalid or expired request").into_response();
        }
    };

    if form.password.len() > MAX_PASSWORD_BYTES {
        state.rate_limiter.record_failure(&ip, now);
        return render_auth_error(&state, &pending, now).await;
    }

    let stored_username = match state.db.get_setup_value("admin_username").await {
        Ok(Some(u)) => u,
        _ => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "setup incomplete").into_response();
        }
    };
    let stored_hash = match state.db.get_setup_value("admin_password_hash").await {
        Ok(Some(h)) => h,
        _ => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "setup incomplete").into_response();
        }
    };

    use sha2::{Digest, Sha256};
    let username_ok = constant_time_eq::constant_time_eq(
        Sha256::digest(form.username.as_bytes()).as_slice(),
        Sha256::digest(stored_username.as_bytes()).as_slice(),
    );

    let parsed_hash = PasswordHash::new(&stored_hash).ok();
    let password_ok = parsed_hash
        .as_ref()
        .map(|h| Argon2::default().verify_password(form.password.as_bytes(), h).is_ok())
        .unwrap_or(false);

    if !username_ok || !password_ok {
        state.rate_limiter.record_failure(&ip, now);
        return render_auth_error(&state, &pending, now).await;
    }

    state.rate_limiter.record_success(&ip);

    let code = random_base64url(32);
    let expires_at = now + 600;

    if let Err(e) = state
        .db
        .insert_auth_code(&AuthCode {
            code: code.clone(),
            client_id: pending.client_id.clone(),
            redirect_uri: pending.redirect_uri.clone(),
            code_challenge: pending.code_challenge.clone(),
            agent_id: pending.agent_id.clone(),
            expires_at,
            used: false,
        })
        .await
    {
        tracing::error!(err = %e, "authorize: db error inserting auth code");
        return (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response();
    }

    let location = append_query_params(
        &pending.redirect_uri,
        &[("code", &code), ("state", &pending.state)],
    );

    Redirect::to(&location).into_response()
}

fn redirect_with_error(redirect_uri: &str, error: &str, state_param: Option<&str>) -> Response {
    let mut pairs: Vec<(&str, &str)> = vec![("error", error)];
    let state_owned;
    if let Some(s) = state_param {
        state_owned = s.to_string();
        pairs.push(("state", &state_owned));
    }
    Redirect::to(&append_query_params(redirect_uri, &pairs)).into_response()
}

/// Append key=value pairs to a URI, using '?' or '&' as appropriate.
fn append_query_params(base: &str, params: &[(&str, &str)]) -> String {
    let sep = if base.contains('?') { '&' } else { '?' };
    let mut out = base.to_string();
    for (i, (k, v)) in params.iter().enumerate() {
        out.push(if i == 0 { sep } else { '&' });
        out.push_str(k);
        out.push('=');
        out.push_str(&urlenccode(v));
    }
    out
}

/// On credential failure: re-insert a fresh pending entry so the user can retry
/// without restarting the entire OAuth flow. After MAX_AUTH_ATTEMPTS failures,
/// abort the flow entirely by redirecting with access_denied.
async fn render_auth_error(state: &Arc<AppState>, pending: &PendingAuthRequest, now: i64) -> Response {
    let new_attempts = pending.attempts.saturating_add(1);
    if new_attempts >= MAX_AUTH_ATTEMPTS {
        return redirect_with_error(&pending.redirect_uri, "access_denied", Some(&pending.state));
    }

    let name = state
        .db
        .get_client_name(&pending.client_id)
        .await
        .unwrap_or_default()
        .unwrap_or_default();

    let new_request_id = random_base64url(16);
    state.pending_auth.insert(
        new_request_id.clone(),
        PendingAuthRequest {
            client_id: pending.client_id.clone(),
            redirect_uri: pending.redirect_uri.clone(),
            code_challenge: pending.code_challenge.clone(),
            state: pending.state.clone(),
            agent_id: pending.agent_id.clone(),
            created_at: now,
            attempts: new_attempts,
        },
    );

    let issuer = match state.db.get_setup_value("issuer_url").await {
        Ok(Some(u)) => u,
        _ => String::new(),
    };
    let action_url = format!("{}/oauth/authorize", issuer.trim_end_matches('/'));

    let html = LOGIN_FORM
        .replace("{CLIENT_NAME}", &html_escape(&name))
        .replace("{REQUEST_ID}", &html_escape(&new_request_id))
        .replace("{ACTION_URL}", &html_escape(&action_url))
        .replace("{ERROR}", r#"<p class="error">Invalid credentials.</p>"#);

    axum::http::Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("content-type", "text/html; charset=utf-8")
        .header("content-security-policy", make_csp(&issuer))
        .header("x-frame-options", "DENY")
        .header("referrer-policy", "no-referrer")
        .body(axum::body::Body::from(html))
        .expect("valid response headers")
}

pub fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn urlenccode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{:02X}", b));
            }
        }
    }
    out
}
