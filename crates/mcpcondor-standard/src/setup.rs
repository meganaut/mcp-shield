// Setup wizard routes
// GET  /setup       — render HTML form (redirects to /ui if already set up)
// POST /setup       — validate + save admin credentials + server URL
// GET  /setup/done  — redirects to /ui/login

use std::sync::Arc;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use axum::Form;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::handler::AppState;
use crate::oauth::authorize::html_escape;

const MAX_PASSWORD_BYTES: usize = 1024;

// Allow loading /assets/* for DaisyUI + Tailwind; inline script needed for theme init
const CSP: &str = "default-src 'none'; style-src 'self'; script-src 'self' 'unsafe-inline'; form-action 'self'";

static SETUP_PAGE: &str = r##"<!DOCTYPE html>
<html lang="en" data-theme="light" id="html-root">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MCPCondor Setup</title>
  <link rel="stylesheet" href="/assets/daisyui.css">
  <script src="/assets/tailwind.js"></script>
  <script>
    (function() {
      var t = localStorage.getItem('mcpcondor-theme') || 'system';
      var r = document.getElementById('html-root');
      if (t === 'dark') r.setAttribute('data-theme', 'dark');
      else if (t === 'light') r.setAttribute('data-theme', 'light');
      else if (window.matchMedia('(prefers-color-scheme: dark)').matches) r.setAttribute('data-theme', 'dark');
    })();
  </script>
</head>
<body class="bg-base-200 min-h-screen flex items-center justify-center p-4">
  <div class="w-full max-w-md">

    <!-- Logo + brand -->
    <div class="flex flex-col items-center mb-8">
      <svg xmlns="http://www.w3.org/2000/svg" class="h-14 w-14 text-primary mb-3" viewBox="0 0 100 100">
        <path d="M36,50 A16,16 0 0,1 64,50" fill="none" stroke="currentColor" stroke-width="5" stroke-linecap="round"/>
        <path d="M28,46 A24,24 0 0,1 72,46" fill="none" stroke="currentColor" stroke-width="5" stroke-linecap="round" opacity="0.5"/>
        <path d="M40,52 C28,46 14,38 4,34 L2,38 L9,42 L2,46 L9,50 L3,54 C12,60 28,62 40,60Z" fill="currentColor"/>
        <path d="M60,52 C72,46 86,38 96,34 L98,38 L91,42 L98,46 L91,50 L97,54 C88,60 72,62 60,60Z" fill="currentColor"/>
        <ellipse cx="50" cy="56" rx="16" ry="12" fill="white"/>
        <circle cx="50" cy="56" r="10" fill="currentColor"/>
        <circle cx="50" cy="56" r="5" fill="#1e1b4b"/>
        <path d="M44,70 L35,88 L43,80 L48,86 L50,81 L52,86 L57,80 L65,88 L56,70Z" fill="currentColor"/>
      </svg>
      <h1 class="text-2xl font-bold tracking-tight">MCPCondor</h1>
      <p class="text-base-content/50 text-sm mt-1">Initial Setup</p>
    </div>

    <!-- Card -->
    <div class="card bg-base-100 shadow-xl">
      <div class="card-body gap-5">

        {ERRORS}

        <form method="POST" action="/setup" class="flex flex-col gap-4">
          <input type="hidden" name="csrf_token" value="{CSRF_TOKEN}">

          <div class="form-control gap-1">
            <label class="label py-0"><span class="label-text font-medium">Admin username</span></label>
            <input type="text" name="admin_username" value="{USERNAME}" required autocomplete="username"
                   class="input input-bordered w-full">
          </div>

          <div class="form-control gap-1">
            <label class="label py-0"><span class="label-text font-medium">Admin password</span></label>
            <input type="password" name="admin_password" required autocomplete="new-password"
                   class="input input-bordered w-full">
            <p class="text-xs text-base-content/50 mt-0.5">Minimum 12 characters</p>
          </div>

          <div class="form-control gap-1">
            <label class="label py-0"><span class="label-text font-medium">Confirm password</span></label>
            <input type="password" name="admin_password_confirm" required autocomplete="new-password"
                   class="input input-bordered w-full">
          </div>

          <div class="form-control gap-1">
            <label class="label py-0"><span class="label-text font-medium">Server URL</span></label>
            <input type="url" name="issuer_url" value="{ISSUER}" required
                   class="input input-bordered w-full" placeholder="http://localhost:3000">
            <p class="text-xs text-base-content/50 mt-0.5 leading-relaxed">
              The URL where this MCPCondor instance is reachable, used by AI agents to
              discover authentication endpoints. Use the address you browse to right now
              (e.g. <code class="font-mono">http://localhost:3000</code>), or your public
              domain in production.
            </p>
          </div>

          <button type="submit" class="btn btn-primary w-full mt-2">Complete Setup</button>
        </form>

      </div>
    </div>
  </div>
</body>
</html>"##;

pub async fn get_setup(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if matches!(state.db.is_setup_complete().await, Ok(true)) {
        return Redirect::to("/ui").into_response();
    }
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    let default_issuer = if host.starts_with("localhost") || host.starts_with("127.") || host.starts_with("[::1]") {
        format!("http://{}", host)
    } else {
        format!("https://{}", host)
    };
    html_response(render_page(&state.setup_csrf_token, &[], "", &default_issuer))
}

pub async fn get_setup_done() -> Response {
    Redirect::to("/ui/login").into_response()
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
    match state.db.is_setup_complete().await {
        Ok(true) => return (StatusCode::GONE, "Setup already complete").into_response(),
        Err(e) => {
            tracing::error!(err = %e, "setup: db error checking setup state");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response();
        }
        Ok(false) => {}
    }

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
        && !form.issuer_url.starts_with("http://127.")
    {
        errors.push("Server URL must start with https:// (production) or http://localhost / http://127. (local).");
    }

    if !errors.is_empty() {
        return html_response(render_page(
            &state.setup_csrf_token,
            &errors,
            &form.admin_username,
            &form.issuer_url,
        ));
    }

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = match argon2.hash_password(form.admin_password.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(e) => {
            tracing::error!(err = %e, "setup: failed to hash password");
            return html_response(render_page(
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
        return html_response(render_page(
            &state.setup_csrf_token,
            &["Setup failed. Check server logs."],
            &form.admin_username,
            &form.issuer_url,
        ));
    }

    Redirect::to("/setup/done").into_response()
}

fn render_page(csrf_token: &str, errors: &[&str], username: &str, issuer: &str) -> String {
    let errors_html = if errors.is_empty() {
        String::new()
    } else {
        let items: String = errors
            .iter()
            .map(|e| format!("<li>{}</li>", html_escape(e)))
            .collect();
        format!(r#"<div role="alert" class="alert alert-error text-sm"><ul class="list-disc list-inside space-y-0.5">{items}</ul></div>"#)
    };
    SETUP_PAGE
        .replace("{CSRF_TOKEN}", &html_escape(csrf_token))
        .replace("{ERRORS}", &errors_html)
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
