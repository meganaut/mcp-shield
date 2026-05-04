use crate::pages::*;

pub fn dashboard() -> DashboardPage {
    DashboardPage {
        stats: DashboardStats {
            integrations_connected: 3,
            integrations_total: 4,
            agents_active: 7,
            agents_total: 9,
            calls_today: 1482,
            calls_denied_today: 14,
            profiles_total: 3,
        },
        recent_events: vec![
            AuditEventRow { time_ago: "2s ago".into(), agent_name: "claude-code".into(), operation_name: "gmail__list_threads".into(), outcome: "allowed".into(), latency_ms: 43 },
            AuditEventRow { time_ago: "8s ago".into(), agent_name: "claude-code".into(), operation_name: "gmail__send_email".into(), outcome: "denied:policy deny".into(), latency_ms: 2 },
            AuditEventRow { time_ago: "1m ago".into(), agent_name: "ci-agent".into(), operation_name: "github__create_pr".into(), outcome: "allowed".into(), latency_ms: 310 },
            AuditEventRow { time_ago: "3m ago".into(), agent_name: "assistant".into(), operation_name: "gcal__list_events".into(), outcome: "allowed".into(), latency_ms: 67 },
            AuditEventRow { time_ago: "5m ago".into(), agent_name: "assistant".into(), operation_name: "slack__post_message".into(), outcome: "allowed".into(), latency_ms: 125 },
        ],
    }
}

pub fn integrations() -> IntegrationsPage {
    IntegrationsPage {
        integrations: vec![
            IntegrationRow { id: "1".into(), slug: "gmail".into(), name: "Gmail".into(), mcp_url: "https://gmail-mcp.example.com".into(), connected: true, tool_count: 12, default_stance: "deny".into() },
            IntegrationRow { id: "2".into(), slug: "gcal".into(), name: "Google Calendar".into(), mcp_url: "https://gcal-mcp.example.com".into(), connected: true, tool_count: 8, default_stance: "deny".into() },
            IntegrationRow { id: "3".into(), slug: "github".into(), name: "GitHub".into(), mcp_url: "https://github-mcp.example.com".into(), connected: true, tool_count: 31, default_stance: "allow".into() },
            IntegrationRow { id: "4".into(), slug: "slack".into(), name: "Slack".into(), mcp_url: "https://slack-mcp.example.com".into(), connected: false, tool_count: 0, default_stance: "deny".into() },
        ],
    }
}

pub fn agents() -> AgentsPage {
    AgentsPage {
        agents: vec![
            AgentRow { id: "a1".into(), name: "claude-code".into(), agent_type: "attended".into(), profile_name: "Read Only".into(), active_sessions: 1, created_at: "2026-04-01".into() },
            AgentRow { id: "a2".into(), name: "assistant".into(), agent_type: "attended".into(), profile_name: "Full Access".into(), active_sessions: 2, created_at: "2026-04-02".into() },
            AgentRow { id: "a3".into(), name: "ci-agent".into(), agent_type: "unattended".into(), profile_name: "CI Profile".into(), active_sessions: 0, created_at: "2026-04-10".into() },
            AgentRow { id: "a4".into(), name: "researcher".into(), agent_type: "attended".into(), profile_name: "Default".into(), active_sessions: 0, created_at: "2026-05-01".into() },
        ],
    }
}

pub fn profiles() -> ProfilesPage {
    ProfilesPage {
        profiles: vec![
            ProfileRow { id: "p1".into(), name: "Default".into(), description: Some("Base profile for new agents".into()), agent_count: 1, is_default: true },
            ProfileRow { id: "p2".into(), name: "Read Only".into(), description: Some("Read access across all integrations, no writes".into()), agent_count: 3, is_default: false },
            ProfileRow { id: "p3".into(), name: "Full Access".into(), description: Some("All tools permitted".into()), agent_count: 2, is_default: false },
            ProfileRow { id: "p4".into(), name: "CI Profile".into(), description: Some("GitHub and Slack write access for CI pipelines".into()), agent_count: 1, is_default: false },
        ],
    }
}

pub fn audit() -> AuditPage {
    let rows = vec![
        AuditRow { time: "2026-05-04 14:23:01".into(), agent_name: "claude-code".into(), operation_name: "gmail__list_threads".into(), outcome: "allowed".into(), latency_ms: 43 },
        AuditRow { time: "2026-05-04 14:22:55".into(), agent_name: "claude-code".into(), operation_name: "gmail__send_email".into(), outcome: "denied:policy deny".into(), latency_ms: 2 },
        AuditRow { time: "2026-05-04 14:20:10".into(), agent_name: "ci-agent".into(), operation_name: "github__create_pr".into(), outcome: "allowed".into(), latency_ms: 310 },
        AuditRow { time: "2026-05-04 14:18:44".into(), agent_name: "assistant".into(), operation_name: "gcal__list_events".into(), outcome: "allowed".into(), latency_ms: 67 },
        AuditRow { time: "2026-05-04 14:15:30".into(), agent_name: "assistant".into(), operation_name: "slack__post_message".into(), outcome: "allowed".into(), latency_ms: 125 },
        AuditRow { time: "2026-05-04 14:10:02".into(), agent_name: "researcher".into(), operation_name: "gmail__get_email".into(), outcome: "allowed".into(), latency_ms: 88 },
        AuditRow { time: "2026-05-04 14:05:17".into(), agent_name: "ci-agent".into(), operation_name: "github__list_prs".into(), outcome: "allowed".into(), latency_ms: 201 },
        AuditRow { time: "2026-05-04 14:02:59".into(), agent_name: "claude-code".into(), operation_name: "gmail__delete_email".into(), outcome: "denied:policy deny".into(), latency_ms: 1 },
    ];
    AuditPage {
        rows,
        filter_agent: None,
        filter_outcome: None,
        page: 1,
        total_pages: 12,
    }
}

pub fn login(error: Option<String>) -> LoginPage {
    LoginPage { error }
}
