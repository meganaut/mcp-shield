use askama::Template;

// ── Login ─────────────────────────────────────────────────────────────────────

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginPage {
    pub error: Option<String>,
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

pub struct DashboardStats {
    pub integrations_connected: u32,
    pub integrations_total: u32,
    pub agents_active: u32,
    pub agents_total: u32,
    pub calls_today: u32,
    pub calls_denied_today: u32,
    pub profiles_total: u32,
}

pub struct AuditEventRow {
    pub time_ago: String,
    pub agent_name: String,
    pub operation_name: String,
    pub outcome: String,
    pub latency_ms: u64,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardPage {
    pub stats: DashboardStats,
    pub recent_events: Vec<AuditEventRow>,
}

// ── Integrations ──────────────────────────────────────────────────────────────

pub struct IntegrationRow {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub mcp_url: String,
    pub connected: bool,
    pub tool_count: u32,
    pub default_stance: String,
}

#[derive(Template)]
#[template(path = "integrations.html")]
pub struct IntegrationsPage {
    pub integrations: Vec<IntegrationRow>,
}

// ── Agents ────────────────────────────────────────────────────────────────────

pub struct AgentRow {
    pub id: String,
    pub name: String,
    pub agent_type: String,
    pub profile_name: String,
    pub active_sessions: u32,
    pub created_at: String,
}

#[derive(Template)]
#[template(path = "agents.html")]
pub struct AgentsPage {
    pub agents: Vec<AgentRow>,
}

// ── Profiles ──────────────────────────────────────────────────────────────────

pub struct ProfileRow {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub agent_count: u32,
    pub is_default: bool,
}

#[derive(Template)]
#[template(path = "profiles.html")]
pub struct ProfilesPage {
    pub profiles: Vec<ProfileRow>,
}

// ── Audit log ─────────────────────────────────────────────────────────────────

pub struct AuditRow {
    pub time: String,
    pub agent_name: String,
    pub operation_name: String,
    pub outcome: String,
    pub latency_ms: u64,
}

#[derive(Template)]
#[template(path = "audit.html")]
pub struct AuditPage {
    pub rows: Vec<AuditRow>,
    pub filter_agent: Option<String>,
    pub filter_outcome: Option<String>,
    pub page: u32,
    pub total_pages: u32,
}

// ── Profile detail ────────────────────────────────────────────────────────────

pub struct ProfileToolRow {
    pub local_name: String,
    pub full_name: String,
    pub description: Option<String>,
    pub allowed: bool,
    /// "read", "write", or "unknown"
    pub access_type: String,
    /// "profile" | "global_deny" | "global_allow"
    pub effective_state: String,
}

pub struct ProfileToolGroup {
    pub integration_slug: String,
    pub integration_name: String,
    pub allowed_count: usize,
    pub tool_count: usize,
    pub tools: Vec<ProfileToolRow>,
}

#[derive(Template)]
#[template(path = "profile_detail.html")]
pub struct ProfileDetailPage {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub is_default: bool,
    pub agent_count: u32,
    pub groups_count: usize,
    pub groups: Vec<ProfileToolGroup>,
    pub allowed_total: usize,
    pub tool_total: usize,
}

// ── Agent detail ──────────────────────────────────────────────────────────────

pub struct AgentSessionRow {
    pub token_prefix: String,
    pub created_at: String,
    pub last_used: String,
    pub expires_at: String,
}

pub struct AgentOverrideRow {
    pub tool_name: String,
    pub allowed: bool,
    /// "static" | "until" | "uses"
    pub kind: String,
    pub expires_at: Option<String>,
    pub near_expiry: bool,
    /// Pre-formatted label like "7 uses remaining"
    pub remaining_label: Option<String>,
}

#[derive(Template)]
#[template(path = "agent_detail.html")]
pub struct AgentDetailPage {
    pub id: String,
    pub name: String,
    pub agent_type: String,
    pub profile_id: String,
    pub profile_name: String,
    pub created_at: String,
    pub sessions: Vec<AgentSessionRow>,
    pub overrides: Vec<AgentOverrideRow>,
    pub overrides_count: usize,
}

// ── Integration tools ─────────────────────────────────────────────────────────

pub struct IntegrationToolRow {
    pub local_name: String,
    pub full_name: String,
    pub description: Option<String>,
    /// "read" or "write"
    pub access_type: String,
}

#[derive(Template)]
#[template(path = "integration_tools.html")]
pub struct IntegrationToolsPage {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub mcp_url: String,
    pub connected: bool,
    pub tool_count: usize,
    pub tools: Vec<IntegrationToolRow>,
}
