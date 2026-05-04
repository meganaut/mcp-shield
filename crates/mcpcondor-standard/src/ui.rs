use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use askama::Template;
use axum::Form;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{DateTime, Utc};
use mcpcondor_db::types::AgentOverrideKind;
use mcpcondor_ui::pages::{
    AgentDetailPage, AgentOverrideRow, AgentRow, AgentSessionRow, AgentsPage,
    AuditEventRow, AuditPage, AuditRow, DashboardPage, DashboardStats,
    IntegrationRow, IntegrationToolRow, IntegrationToolsPage, IntegrationsPage,
    LoginPage, ProfileDetailPage, ProfileRow, ProfileToolGroup, ProfileToolRow,
    ProfilesPage,
};
use ring::hmac;
use serde::Deserialize;

use crate::crypto::unix_timestamp_secs;
use crate::handler::AppState;

const COOKIE_NAME: &str = "mcs";
const SESSION_SECS: i64 = 8 * 3600;

// ─── Cookie auth ──────────────────────────────────────────────────────────────

fn make_admin_cookie(key: &[u8; 32]) -> String {
    let expires = unix_timestamp_secs() + SESSION_SECS;
    let msg = expires.to_string();
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&hmac_key, msg.as_bytes());
    let sig = hex::encode(tag.as_ref());
    format!(
        "{}={}.{}; Max-Age={}; Path=/; HttpOnly; SameSite=Strict",
        COOKIE_NAME, expires, sig, SESSION_SECS
    )
}

fn verify_admin_cookie(headers: &HeaderMap, key: &[u8; 32]) -> bool {
    let cookie_str = match headers.get("cookie").and_then(|v| v.to_str().ok()) {
        Some(c) => c,
        None => return false,
    };
    let value = cookie_str
        .split(';')
        .map(|s| s.trim())
        .find_map(|s| s.strip_prefix(&format!("{}=", COOKIE_NAME)))
        .unwrap_or("");

    let (expires_str, sig) = match value.split_once('.') {
        Some(p) => p,
        None => return false,
    };
    let expires: i64 = match expires_str.parse() {
        Ok(e) => e,
        Err(_) => return false,
    };
    if expires < unix_timestamp_secs() {
        return false;
    }
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let expected = hex::encode(hmac::sign(&hmac_key, expires_str.as_bytes()).as_ref());
    constant_time_eq::constant_time_eq(sig.as_bytes(), expected.as_bytes())
}

fn require_admin(headers: &HeaderMap, key: &[u8; 32]) -> Result<(), Response> {
    if verify_admin_cookie(headers, key) {
        Ok(())
    } else {
        Err(Redirect::to("/ui/login").into_response())
    }
}

fn render<T: Template>(t: T) -> Response {
    match t.render() {
        Ok(html) => axum::http::Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/html; charset=utf-8")
            .body(axum::body::Body::from(html))
            .expect("valid response"),
        Err(e) => {
            tracing::error!("template render error: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

// ─── Login / logout ───────────────────────────────────────────────────────────

pub async fn get_ui_login(headers: HeaderMap, State(state): State<Arc<AppState>>) -> Response {
    // Already logged in → redirect to dashboard
    if verify_admin_cookie(&headers, &state.admin_session_key) {
        return Redirect::to("/ui").into_response();
    }
    render(LoginPage { error: None })
}

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
}

pub async fn post_ui_login(
    State(state): State<Arc<AppState>>,
    Form(form): Form<LoginForm>,
) -> Response {
    let valid = async {
        let stored_user = state
            .db
            .get_setup_value("admin_username")
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
        if stored_user.is_empty() || form.username != stored_user {
            return false;
        }
        let stored_hash = state
            .db
            .get_setup_value("admin_password_hash")
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
        if stored_hash.is_empty() {
            return false;
        }
        let Ok(parsed) = PasswordHash::new(&stored_hash) else { return false; };
        Argon2::default()
            .verify_password(form.password.as_bytes(), &parsed)
            .is_ok()
    }
    .await;

    if valid {
        axum::http::Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header("location", "/ui")
            .header("set-cookie", make_admin_cookie(&state.admin_session_key))
            .body(axum::body::Body::empty())
            .expect("valid response")
    } else {
        render(LoginPage {
            error: Some("Invalid username or password".to_string()),
        })
    }
}

pub async fn post_ui_logout() -> Response {
    axum::http::Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header("location", "/ui/login")
        .header(
            "set-cookie",
            format!("{}=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict", COOKIE_NAME),
        )
        .body(axum::body::Body::empty())
        .expect("valid response")
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn fmt_date_secs(secs: i64) -> String {
    DateTime::<Utc>::from_timestamp(secs, 0)
        .map(|dt| dt.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "—".to_string())
}

fn fmt_datetime_ms(ms: i64) -> String {
    DateTime::<Utc>::from_timestamp_millis(ms)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| "—".to_string())
}

fn fmt_datetime_secs(secs: i64) -> String {
    DateTime::<Utc>::from_timestamp(secs, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| "—".to_string())
}

fn time_ago_ms(ms: i64) -> String {
    let secs = (Utc::now().timestamp_millis() - ms).max(0) / 1000;
    if secs < 60 {
        format!("{}s ago", secs)
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86400)
    }
}

fn classify_access(name: &str) -> &'static str {
    const WRITE: &[&str] = &[
        "create", "update", "delete", "remove", "send", "post", "write", "modify", "set", "add",
        "insert", "edit", "patch", "push", "publish", "archive", "move", "rename", "destroy",
        "merge", "fork", "submit", "upload", "draft", "label", "mark",
    ];
    let lower = name.to_lowercase();
    if WRITE.iter().any(|p| lower.contains(p)) {
        "write"
    } else {
        "read"
    }
}

fn resolve_agent_name(agent_id: &str, names: &HashMap<String, String>) -> String {
    names
        .get(agent_id)
        .cloned()
        .unwrap_or_else(|| format!("{}…", &agent_id[..8.min(agent_id.len())]))
}

// ─── Dashboard ────────────────────────────────────────────────────────────────

pub async fn get_ui_dashboard(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = require_admin(&headers, &state.admin_session_key) {
        return r;
    }

    let (integrations, clients, profiles) = tokio::join!(
        state.db.list_integrations(),
        state.db.list_oauth_clients(),
        state.db.list_profiles(),
    );
    let integrations = integrations.unwrap_or_default();
    let clients = clients.unwrap_or_default();
    let profiles = profiles.unwrap_or_default();

    let integrations_connected = integrations.iter().filter(|i| i.connected).count() as u32;
    let integrations_total = integrations.len() as u32;
    let agents_total = clients.len() as u32;
    let profiles_total = profiles.len() as u32;

    let agents_active = state
        .sessions
        .iter()
        .map(|e| e.agent_id.clone())
        .collect::<HashSet<_>>()
        .len() as u32;

    let today_start_ms = {
        let now = Utc::now();
        let midnight = now
            .date_naive()
            .and_hms_opt(0, 0, 0)
            .unwrap_or_default();
        DateTime::<Utc>::from_naive_utc_and_offset(midnight, Utc).timestamp_millis()
    };
    let (calls_today, calls_denied_today) = state
        .db
        .count_audit_events_since(today_start_ms)
        .await
        .unwrap_or((0, 0));

    let name_map: HashMap<String, String> = clients
        .iter()
        .map(|c| (c.agent_id.clone(), c.client_name.clone()))
        .collect();

    let recent = state.db.list_all_audit_events(5).await.unwrap_or_default();
    let recent_events = recent
        .into_iter()
        .map(|e| AuditEventRow {
            time_ago: time_ago_ms(e.timestamp_ms),
            agent_name: resolve_agent_name(&e.agent_id, &name_map),
            operation_name: e.operation_name,
            outcome: e.outcome,
            latency_ms: e.latency_ms as u64,
        })
        .collect();

    render(DashboardPage {
        stats: DashboardStats {
            integrations_connected,
            integrations_total,
            agents_active,
            agents_total,
            calls_today: calls_today as u32,
            calls_denied_today: calls_denied_today as u32,
            profiles_total,
        },
        recent_events,
    })
}

// ─── Integrations ─────────────────────────────────────────────────────────────

pub async fn get_ui_integrations(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = require_admin(&headers, &state.admin_session_key) {
        return r;
    }
    let integrations = state.db.list_integrations().await.unwrap_or_default();
    let mut rows = Vec::new();
    for int in integrations {
        let tool_count = if let Some(ds) = state.downstreams.get(&int.slug) {
            ds.value().list_tools().await.len() as u32
        } else {
            0
        };
        rows.push(IntegrationRow {
            id: int.id,
            slug: int.slug,
            name: int.name,
            mcp_url: int.mcp_url,
            connected: int.connected,
            tool_count,
            default_stance: if int.default_stance {
                "allow".to_string()
            } else {
                "deny".to_string()
            },
        });
    }
    render(IntegrationsPage { integrations: rows })
}

pub async fn get_ui_integration_tools(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(r) = require_admin(&headers, &state.admin_session_key) {
        return r;
    }
    let integration = match state.db.get_integration(&id).await.ok().flatten() {
        Some(i) => i,
        None => return StatusCode::NOT_FOUND.into_response(),
    };
    let tools = if let Some(ds) = state.downstreams.get(&integration.slug) {
        ds.value().list_tools().await
    } else {
        Default::default()
    };
    let tool_count = tools.len();
    let tool_rows = tools
        .iter()
        .map(|t| IntegrationToolRow {
            full_name: format!("{}__{}", integration.slug, t.name),
            access_type: classify_access(&t.name).to_string(),
            description: t.description.clone(),
            local_name: t.name.clone(),
        })
        .collect();
    render(IntegrationToolsPage {
        id: integration.id,
        slug: integration.slug.clone(),
        name: integration.name,
        mcp_url: integration.mcp_url,
        connected: integration.connected,
        tool_count,
        tools: tool_rows,
    })
}

// ─── Agents ───────────────────────────────────────────────────────────────────

pub async fn get_ui_agents(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = require_admin(&headers, &state.admin_session_key) {
        return r;
    }
    let (clients, profiles) = tokio::join!(
        state.db.list_oauth_clients(),
        state.db.list_profiles(),
    );
    let clients = clients.unwrap_or_default();
    let profiles = profiles.unwrap_or_default();

    let profile_names: HashMap<String, String> =
        profiles.iter().map(|p| (p.id.clone(), p.name.clone())).collect();
    let default_name = profiles
        .iter()
        .find(|p| p.is_default)
        .map(|p| p.name.as_str())
        .unwrap_or("Default")
        .to_string();

    let mut session_counts: HashMap<String, u32> = HashMap::new();
    for entry in state.sessions.iter() {
        *session_counts.entry(entry.agent_id.clone()).or_insert(0) += 1;
    }

    let mut rows = Vec::new();
    for client in clients {
        let profile_id = state
            .db
            .get_agent_profile_id(&client.agent_id)
            .await
            .ok()
            .flatten();
        let profile_name = profile_id
            .as_deref()
            .and_then(|id| profile_names.get(id))
            .cloned()
            .unwrap_or_else(|| default_name.clone());
        let active = *session_counts.get(&client.agent_id).unwrap_or(&0);
        rows.push(AgentRow {
            id: client.agent_id,
            name: client.client_name,
            agent_type: if active > 0 { "attended" } else { "unattended" }.to_string(),
            profile_name,
            active_sessions: active,
            created_at: fmt_date_secs(client.created_at),
        });
    }
    render(AgentsPage { agents: rows })
}

pub async fn get_ui_agent_detail(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
) -> Response {
    if let Err(r) = require_admin(&headers, &state.admin_session_key) {
        return r;
    }
    let clients = state.db.list_oauth_clients().await.unwrap_or_default();
    let client = match clients.into_iter().find(|c| c.agent_id == agent_id) {
        Some(c) => c,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    let profiles = state.db.list_profiles().await.unwrap_or_default();
    let profile_id_opt = state
        .db
        .get_agent_profile_id(&agent_id)
        .await
        .ok()
        .flatten();
    let profile = profile_id_opt
        .as_deref()
        .and_then(|pid| profiles.iter().find(|p| p.id == pid))
        .or_else(|| profiles.iter().find(|p| p.is_default));
    let (profile_id, profile_name) = profile
        .map(|p| (p.id.clone(), p.name.clone()))
        .unwrap_or_else(|| (String::new(), "Default".to_string()));

    // MCP sessions filtered by this agent
    let now_instant = std::time::Instant::now();
    let sessions: Vec<AgentSessionRow> = state
        .sessions
        .iter()
        .filter(|e| e.agent_id == agent_id)
        .map(|e| {
            let elapsed_secs = now_instant.duration_since(e.created_at).as_secs() as i64;
            let created_unix = unix_timestamp_secs() - elapsed_secs;
            AgentSessionRow {
                token_prefix: format!("{}…", &e.id[..8.min(e.id.len())]),
                created_at: fmt_datetime_secs(created_unix),
                last_used: "active".to_string(),
                expires_at: fmt_date_secs(created_unix + 86400),
            }
        })
        .collect();

    let overrides_raw = state
        .db
        .list_agent_overrides(&agent_id)
        .await
        .unwrap_or_default();
    let now_ms = unix_timestamp_secs() * 1000;
    let overrides: Vec<AgentOverrideRow> = overrides_raw
        .into_iter()
        .map(|o| {
            let (kind, expires_at, near_expiry, remaining_label) = match &o.kind {
                AgentOverrideKind::Static => ("static".to_string(), None, false, None),
                AgentOverrideKind::Until { expires_at } => {
                    let near = expires_at - now_ms < 3_600_000;
                    ("until".to_string(), Some(fmt_datetime_ms(*expires_at)), near, None)
                }
                AgentOverrideKind::Uses { remaining } => {
                    let label = format!(
                        "{} use{} remaining",
                        remaining,
                        if *remaining == 1 { "" } else { "s" }
                    );
                    ("uses".to_string(), None, false, Some(label))
                }
            };
            AgentOverrideRow {
                tool_name: o.tool_name,
                allowed: o.allowed,
                kind,
                expires_at,
                near_expiry,
                remaining_label,
            }
        })
        .collect();

    let overrides_count = overrides.len();
    render(AgentDetailPage {
        id: client.agent_id,
        name: client.client_name,
        agent_type: if sessions.is_empty() { "unattended" } else { "attended" }.to_string(),
        profile_id,
        profile_name,
        created_at: fmt_date_secs(client.created_at),
        sessions,
        overrides,
        overrides_count,
    })
}

// ─── Profiles ─────────────────────────────────────────────────────────────────

pub async fn get_ui_profiles(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = require_admin(&headers, &state.admin_session_key) {
        return r;
    }
    let (profiles, clients) = tokio::join!(
        state.db.list_profiles(),
        state.db.list_oauth_clients(),
    );
    let profiles = profiles.unwrap_or_default();
    let clients = clients.unwrap_or_default();

    let default_id = profiles
        .iter()
        .find(|p| p.is_default)
        .map(|p| p.id.clone())
        .unwrap_or_default();

    // Count agents per profile (serial to avoid N concurrent queries)
    let mut counts: HashMap<String, u32> = HashMap::new();
    for client in &clients {
        let pid = state
            .db
            .get_agent_profile_id(&client.agent_id)
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| default_id.clone());
        *counts.entry(pid).or_insert(0) += 1;
    }

    let rows = profiles
        .into_iter()
        .map(|p| {
            let agent_count = *counts.get(&p.id).unwrap_or(&0);
            ProfileRow {
                id: p.id,
                name: p.name,
                description: p.description,
                agent_count,
                is_default: p.is_default,
            }
        })
        .collect();
    render(ProfilesPage { profiles: rows })
}

pub async fn get_ui_profile_detail(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> Response {
    if let Err(r) = require_admin(&headers, &state.admin_session_key) {
        return r;
    }
    let profile = match state.db.get_profile(&profile_id).await.ok().flatten() {
        Some(p) => p,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    let (profile_rules, global_rules, integrations, clients) = tokio::join!(
        state.db.list_profile_rules(&profile_id),
        state.db.list_global_rules(),
        state.db.list_integrations(),
        state.db.list_oauth_clients(),
    );
    let profile_rules = profile_rules.unwrap_or_default();
    let global_rules = global_rules.unwrap_or_default();
    let integrations = integrations.unwrap_or_default();
    let clients = clients.unwrap_or_default();

    let pr_map: HashMap<String, bool> = profile_rules
        .into_iter()
        .map(|r| (r.tool_name, r.allowed))
        .collect();
    let gr_map: HashMap<String, bool> = global_rules
        .into_iter()
        .map(|r| (r.tool_name, r.allowed))
        .collect();
    let int_map: HashMap<String, (String, bool)> = integrations
        .iter()
        .map(|i| (i.slug.clone(), (i.name.clone(), i.default_stance)))
        .collect();

    // Count agents assigned to this profile
    let default_id = if profile.is_default {
        profile_id.clone()
    } else {
        String::new()
    };
    let mut agent_count = 0u32;
    for client in &clients {
        let pid = state
            .db
            .get_agent_profile_id(&client.agent_id)
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| default_id.clone());
        if pid == profile_id {
            agent_count += 1;
        }
    }

    let mut groups: Vec<ProfileToolGroup> = Vec::new();
    let mut allowed_total = 0usize;
    let mut tool_total = 0usize;

    for entry in state.downstreams.iter() {
        let slug = entry.key().clone();
        let ds = entry.value().clone();
        let tools = ds.list_tools().await;
        if tools.is_empty() {
            continue;
        }

        let (integration_name, default_stance) = int_map
            .get(&slug)
            .cloned()
            .unwrap_or_else(|| (slug.clone(), false));

        let mut tool_rows = Vec::new();
        let mut group_allowed = 0usize;

        for t in tools.iter() {
            let full_name = format!("{}__{}", slug, t.name);
            let (allowed, effective_state) = match gr_map.get(&full_name) {
                Some(&gr) => (gr, if gr { "global_allow" } else { "global_deny" }),
                None => {
                    let allowed = *pr_map.get(&full_name).unwrap_or(&default_stance);
                    (allowed, "profile")
                }
            };
            if allowed {
                group_allowed += 1;
                allowed_total += 1;
            }
            tool_total += 1;
            tool_rows.push(ProfileToolRow {
                local_name: t.name.clone(),
                full_name,
                description: t.description.clone(),
                allowed,
                access_type: classify_access(&t.name).to_string(),
                effective_state: effective_state.to_string(),
            });
        }

        let tool_count = tool_rows.len();
        groups.push(ProfileToolGroup {
            integration_slug: slug,
            integration_name,
            allowed_count: group_allowed,
            tool_count,
            tools: tool_rows,
        });
    }

    let groups_count = groups.len();
    render(ProfileDetailPage {
        id: profile.id,
        name: profile.name,
        description: profile.description,
        is_default: profile.is_default,
        agent_count,
        groups_count,
        groups,
        allowed_total,
        tool_total,
    })
}

// ─── Profile form actions ─────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateProfileForm {
    pub name: String,
    pub description: Option<String>,
}

pub async fn post_ui_create_profile(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<CreateProfileForm>,
) -> Response {
    if let Err(r) = require_admin(&headers, &state.admin_session_key) {
        return r;
    }
    let id = uuid::Uuid::new_v4().to_string();
    let now_ms = unix_timestamp_secs() * 1000;
    let desc = form.description.filter(|d| !d.is_empty());
    let _ = state
        .db
        .insert_profile(&mcpcondor_db::types::Profile {
            id,
            name: form.name,
            description: desc,
            is_default: false,
            created_at: now_ms,
        })
        .await;
    Redirect::to("/ui/profiles").into_response()
}

#[derive(Deserialize)]
pub struct RenameProfileForm {
    pub name: String,
    pub description: Option<String>,
}

pub async fn post_ui_rename_profile(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
    Form(form): Form<RenameProfileForm>,
) -> Response {
    if let Err(r) = require_admin(&headers, &state.admin_session_key) {
        return r;
    }
    let desc = form.description.as_deref().filter(|d| !d.is_empty());
    let _ = state.db.update_profile(&profile_id, &form.name, desc).await;
    Redirect::to(&format!("/ui/profiles/{}", profile_id)).into_response()
}

// ─── Audit log ────────────────────────────────────────────────────────────────

pub async fn get_ui_audit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = require_admin(&headers, &state.admin_session_key) {
        return r;
    }
    let (clients, events) = tokio::join!(
        state.db.list_oauth_clients(),
        state.db.list_all_audit_events(200),
    );
    let clients = clients.unwrap_or_default();
    let events = events.unwrap_or_default();

    let name_map: HashMap<String, String> = clients
        .iter()
        .map(|c| (c.agent_id.clone(), c.client_name.clone()))
        .collect();

    let rows = events
        .into_iter()
        .map(|e| AuditRow {
            time: fmt_datetime_ms(e.timestamp_ms),
            agent_name: resolve_agent_name(&e.agent_id, &name_map),
            operation_name: e.operation_name,
            outcome: e.outcome,
            latency_ms: e.latency_ms as u64,
        })
        .collect();

    render(AuditPage {
        rows,
        filter_agent: None,
        filter_outcome: None,
        page: 1,
        total_pages: 1,
    })
}
