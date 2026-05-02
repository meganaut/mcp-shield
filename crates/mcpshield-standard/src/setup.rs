// Setup wizard routes — served only when setup_complete = '0'
// GET  /setup       — render HTML form
// POST /setup       — validate + save admin credentials + issuer URL
// GET  /setup/done  — static confirmation page

use std::sync::Arc;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use axum::Form;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::handler::AppState;
use crate::oauth::authorize::html_escape;

/// Argon2 long-input DoS cap — consistent with all other Argon2 call sites
const MAX_PASSWORD_BYTES: usize = 1024;

const CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'";

static SETUP_FORM: &str = r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>MCPShield Setup</title>
<style>
  body { font-family: sans-serif; max-width: 480px; margin: 60px auto; padding: 0 1rem; }
  label { display: block; margin-top: 1rem; font-weight: bold; }
  input { width: 100%; padding: .5rem; margin-top: .25rem; box-sizing: border-box; }
  .error { color: red; font-size: .9em; margin-top: .25rem; }
  button { margin-top: 1.5rem; padding: .6rem 1.5rem; background: #0066cc; color: white; border: none; cursor: pointer; font-size: 1rem; }
  button:hover { background: #0055aa; }
</style>
</head>
<body>
<h1>MCPShield Initial Setup</h1>
<form method="POST" action="/setup">
  <input type="hidden" name="csrf_token" value="{CSRF_TOKEN}">
  {ERRORS}
  <label>Admin username<input type="text" name="admin_username" value="{USERNAME}" required></label>
  <label>Admin password (min 12 chars)<input type="password" name="admin_password" required></label>
  <label>Confirm password<input type="password" name="admin_password_confirm" required></label>
  <label>Issuer URL (https:// or http://localhost)<input type="url" name="issuer_url" value="{ISSUER}" required></label>
  <button type="submit">Complete Setup</button>
</form>
</body>
</html>"#;

static SETUP_DONE: &str = r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>MCPShield Setup Complete</title></head>
<body>
<h1>Setup Complete</h1>
<p>Setup complete. Restart MCPShield to begin.</p>
</body>
</html>"#;

pub async fn get_setup(State(state): State<Arc<AppState>>) -> Response {
    html_response(render_form(&state.setup_csrf_token, &[], "", ""))
}

pub async fn get_setup_done() -> Response {
    axum::http::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .header("content-security-policy", CSP)
        .body(axum::body::Body::from(SETUP_DONE))
        .expect("valid response headers")
}

#[derive(Deserialize)]
pub struct SetupForm {
    pub csrf_token: String,
    pub admin_username: String,
    pub admin_password: String,
    pub admin_password_confirm: String,
    pub issuer_url: String,
}

pub async fn post_setup(
    State(state): State<Arc<AppState>>,
    Form(form): Form<SetupForm>,
) -> Response {
    // Guard against credential hijacking: reject once setup is already complete
    match state.db.is_setup_complete().await {
        Ok(true) => return (StatusCode::GONE, "Setup already complete").into_response(),
        Err(e) => {
            tracing::error!(err = %e, "setup: db error checking setup state");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response();
        }
        Ok(false) => {}
    }

    // CSRF check — constant-time comparison
    if !constant_time_eq::constant_time_eq(
        form.csrf_token.as_bytes(),
        state.setup_csrf_token.as_bytes(),
    ) {
        return (StatusCode::FORBIDDEN, "invalid request").into_response();
    }

    let mut errors: Vec<&str> = Vec::new();

    if form.admin_username.trim().is_empty() {
        errors.push("Admin username must not be empty.");
    }
    if form.admin_password.len() < 12 {
        errors.push("Admin password must be at least 12 characters.");
    }
    if form.admin_password.len() > MAX_PASSWORD_BYTES {
        errors.push("Admin password must not exceed 1024 characters.");
    }
    if form.admin_password != form.admin_password_confirm {
        errors.push("Passwords do not match.");
    }
    if !form.issuer_url.starts_with("https://")
        && !form.issuer_url.starts_with("http://localhost")
    {
        errors.push("Issuer URL must start with https:// or http://localhost.");
    }

    if !errors.is_empty() {
        return html_response(render_form(
            &state.setup_csrf_token,
            &errors,
            &form.admin_username,
            &form.issuer_url,
        ));
    }

    // Hash password with Argon2id
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = match argon2.hash_password(form.admin_password.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(e) => {
            tracing::error!(err = %e, "setup: failed to hash password");
            return html_response(render_form(
                &state.setup_csrf_token,
                &["Setup failed. Check server logs."],
                &form.admin_username,
                &form.issuer_url,
            ));
        }
    };

    let issuer_url = form.issuer_url.trim().trim_end_matches('/');
    if let Err(e) = state
        .db
        .complete_setup(form.admin_username.trim(), &hash, issuer_url)
        .await
    {
        tracing::error!(err = %e, "setup: failed to save setup state");
        return html_response(render_form(
            &state.setup_csrf_token,
            &["Setup failed. Check server logs."],
            &form.admin_username,
            &form.issuer_url,
        ));
    }

    Redirect::to("/setup/done").into_response()
}

fn render_form(csrf_token: &str, errors: &[&str], username: &str, issuer: &str) -> String {
    let error_html: String = errors
        .iter()
        .map(|e| format!(r#"<p class="error">{}</p>"#, html_escape(e)))
        .collect::<Vec<_>>()
        .join("\n");
    SETUP_FORM
        .replace("{CSRF_TOKEN}", &html_escape(csrf_token))
        .replace("{ERRORS}", &error_html)
        .replace("{USERNAME}", &html_escape(username))
        .replace("{ISSUER}", &html_escape(issuer))
}

fn html_response(body: String) -> Response {
    axum::http::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .header("content-security-policy", CSP)
        .header("x-frame-options", "DENY")
        .header("referrer-policy", "no-referrer")
        .body(axum::body::Body::from(body))
        .expect("valid response headers")
}
