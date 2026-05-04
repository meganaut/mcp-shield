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

pub fn profile_detail() -> ProfileDetailPage {
    let gmail_tools = vec![
        ProfileToolRow { local_name: "list_threads".into(), full_name: "gmail__list_threads".into(), description: Some("List email threads matching a query. Supports the full Gmail search syntax including operators such as from:, to:, subject:, has:attachment, is:unread, label:, after:, before:, and boolean operators. Returns thread IDs, snippet, label IDs, and message count. Paginated via nextPageToken.".into()), allowed: true, access_type: "read".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "get_thread".into(), full_name: "gmail__get_thread".into(), description: Some("Get a full email thread by thread ID including all messages, headers, body parts, inline images, and attachment metadata.".into()), allowed: true, access_type: "read".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "get_email".into(), full_name: "gmail__get_email".into(), description: Some("Get a single email message by message ID. Returns the full RFC 2822 message payload including all MIME parts.".into()), allowed: true, access_type: "read".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "search".into(), full_name: "gmail__search".into(), description: Some("Search across all emails using Gmail query syntax. Returns matching thread or message IDs with snippets.".into()), allowed: true, access_type: "read".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "list_labels".into(), full_name: "gmail__list_labels".into(), description: Some("List all Gmail labels including system labels (INBOX, SENT, DRAFT, SPAM, TRASH) and user-created labels.".into()), allowed: true, access_type: "read".into(), effective_state: "global_allow".into() },
        ProfileToolRow { local_name: "get_attachment".into(), full_name: "gmail__get_attachment".into(), description: Some("Download an email attachment by message ID and attachment ID. Returns the attachment data as a base64url-encoded string.".into()), allowed: true, access_type: "read".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "list_drafts".into(), full_name: "gmail__list_drafts".into(), description: Some("List draft messages in the mailbox. Returns draft ID, message ID, and snippet.".into()), allowed: true, access_type: "read".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "send_email".into(), full_name: "gmail__send_email".into(), description: Some("Send an email message on behalf of the authenticated user. Accepts a structured message with to, cc, bcc, subject, body (text and/or HTML), and attachment references. Returns the sent message ID and thread ID.".into()), allowed: false, access_type: "write".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "create_draft".into(), full_name: "gmail__create_draft".into(), description: Some("Create a new draft message without sending it. The draft is saved to the DRAFTS label and can be retrieved, updated, or sent later.".into()), allowed: false, access_type: "write".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "delete_email".into(), full_name: "gmail__delete_email".into(), description: Some("Permanently and immediately delete an email message, bypassing the Trash folder. This action is irreversible and cannot be undone.".into()), allowed: false, access_type: "write".into(), effective_state: "global_deny".into() },
        ProfileToolRow { local_name: "label_message".into(), full_name: "gmail__label_message".into(), description: Some("Apply or remove labels from one or more messages. Can be used to mark messages as read/unread, star/unstar, archive, move to spam, or apply custom labels.".into()), allowed: false, access_type: "write".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "mark_read".into(), full_name: "gmail__mark_read".into(), description: Some("Mark one or more messages as read or unread by modifying the UNREAD system label.".into()), allowed: false, access_type: "unknown".into(), effective_state: "profile".into() },
    ];
    let gcal_tools = vec![
        ProfileToolRow { local_name: "list_events".into(), full_name: "gcal__list_events".into(), description: Some("List upcoming calendar events".into()), allowed: true, access_type: "read".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "get_event".into(), full_name: "gcal__get_event".into(), description: Some("Get details of a specific event".into()), allowed: true, access_type: "read".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "list_calendars".into(), full_name: "gcal__list_calendars".into(), description: Some("List available calendars".into()), allowed: true, access_type: "read".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "suggest_time".into(), full_name: "gcal__suggest_time".into(), description: Some("Find a free meeting slot".into()), allowed: true, access_type: "read".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "create_event".into(), full_name: "gcal__create_event".into(), description: Some("Create a new calendar event".into()), allowed: false, access_type: "write".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "update_event".into(), full_name: "gcal__update_event".into(), description: Some("Update an existing event".into()), allowed: false, access_type: "write".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "delete_event".into(), full_name: "gcal__delete_event".into(), description: Some("Delete a calendar event".into()), allowed: false, access_type: "write".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "respond_to_event".into(), full_name: "gcal__respond_to_event".into(), description: Some("Accept, decline, or maybe an invite".into()), allowed: false, access_type: "write".into(), effective_state: "profile".into() },
    ];
    let github_tools = vec![
        ProfileToolRow { local_name: "list_repos".into(), full_name: "github__list_repos".into(), description: Some("List repositories for a user or org".into()), allowed: true, access_type: "read".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "get_repo".into(), full_name: "github__get_repo".into(), description: Some("Get repository details".into()), allowed: true, access_type: "read".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "list_prs".into(), full_name: "github__list_prs".into(), description: Some("List pull requests".into()), allowed: true, access_type: "read".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "get_pr".into(), full_name: "github__get_pr".into(), description: Some("Get pull request details and diff".into()), allowed: true, access_type: "read".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "list_issues".into(), full_name: "github__list_issues".into(), description: Some("List issues for a repository".into()), allowed: true, access_type: "read".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "get_issue".into(), full_name: "github__get_issue".into(), description: Some("Get issue details and comments".into()), allowed: true, access_type: "read".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "search_code".into(), full_name: "github__search_code".into(), description: Some("Search code across repositories".into()), allowed: true, access_type: "read".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "get_file".into(), full_name: "github__get_file".into(), description: Some("Get file contents from a repository".into()), allowed: true, access_type: "read".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "list_commits".into(), full_name: "github__list_commits".into(), description: Some("List commits on a branch".into()), allowed: true, access_type: "read".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "get_commit".into(), full_name: "github__get_commit".into(), description: Some("Get commit details and diff".into()), allowed: true, access_type: "read".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "create_pr".into(), full_name: "github__create_pr".into(), description: Some("Open a new pull request".into()), allowed: false, access_type: "write".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "merge_pr".into(), full_name: "github__merge_pr".into(), description: Some("Merge a pull request".into()), allowed: false, access_type: "write".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "create_issue".into(), full_name: "github__create_issue".into(), description: Some("Open a new issue".into()), allowed: false, access_type: "write".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "close_issue".into(), full_name: "github__close_issue".into(), description: Some("Close an issue".into()), allowed: false, access_type: "write".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "push_file".into(), full_name: "github__push_file".into(), description: Some("Commit a file to a branch".into()), allowed: false, access_type: "write".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "delete_file".into(), full_name: "github__delete_file".into(), description: Some("Delete a file from a branch".into()), allowed: false, access_type: "write".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "create_branch".into(), full_name: "github__create_branch".into(), description: Some("Create a new branch".into()), allowed: false, access_type: "write".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "delete_branch".into(), full_name: "github__delete_branch".into(), description: Some("Delete a branch".into()), allowed: false, access_type: "write".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "add_comment".into(), full_name: "github__add_comment".into(), description: Some("Comment on an issue or PR".into()), allowed: false, access_type: "write".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "review_pr".into(), full_name: "github__review_pr".into(), description: Some("Submit a pull request review".into()), allowed: false, access_type: "write".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "manage_labels".into(), full_name: "github__manage_labels".into(), description: Some("Create, update, delete labels".into()), allowed: false, access_type: "write".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "manage_milestones".into(), full_name: "github__manage_milestones".into(), description: Some("Create, update, delete milestones".into()), allowed: false, access_type: "write".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "fork_repo".into(), full_name: "github__fork_repo".into(), description: Some("Fork a repository".into()), allowed: false, access_type: "write".into(), effective_state: "profile".into() },
        ProfileToolRow { local_name: "delete_repo".into(), full_name: "github__delete_repo".into(), description: Some("Delete a repository permanently".into()), allowed: false, access_type: "write".into(), effective_state: "global_deny".into() },
    ];

    let gmail_allowed = gmail_tools.iter().filter(|t| t.allowed).count();
    let gcal_allowed = gcal_tools.iter().filter(|t| t.allowed).count();
    let github_allowed = github_tools.iter().filter(|t| t.allowed).count();
    let allowed_total = gmail_allowed + gcal_allowed + github_allowed;
    let tool_total = gmail_tools.len() + gcal_tools.len() + github_tools.len();

    let gmail_count = gmail_tools.len();
    let gcal_count = gcal_tools.len();
    let github_count = github_tools.len();
    let groups = vec![
        ProfileToolGroup { integration_slug: "gmail".into(), integration_name: "Gmail".into(), allowed_count: gmail_allowed, tool_count: gmail_count, tools: gmail_tools },
        ProfileToolGroup { integration_slug: "gcal".into(), integration_name: "Google Calendar".into(), allowed_count: gcal_allowed, tool_count: gcal_count, tools: gcal_tools },
        ProfileToolGroup { integration_slug: "github".into(), integration_name: "GitHub".into(), allowed_count: github_allowed, tool_count: github_count, tools: github_tools },
    ];

    let groups_count = groups.len();
    ProfileDetailPage {
        id: "p2".into(),
        name: "Read Only".into(),
        description: Some("Read access across all integrations, no writes".into()),
        is_default: false,
        agent_count: 3,
        groups_count,
        groups,
        allowed_total,
        tool_total,
    }
}

pub fn agent_detail() -> AgentDetailPage {
    let overrides = vec![
            AgentOverrideRow {
                tool_name: "gmail__send_email".into(),
                allowed: true,
                kind: "until".into(),
                expires_at: Some("2026-05-04 17:00".into()),
                near_expiry: true,
                remaining_label: None,
            },
            AgentOverrideRow {
                tool_name: "github__get_file".into(),
                allowed: true,
                kind: "uses".into(),
                expires_at: None,
                near_expiry: false,
                remaining_label: Some("7 uses remaining".into()),
            },
            AgentOverrideRow {
                tool_name: "github__delete_repo".into(),
                allowed: false,
                kind: "static".into(),
                expires_at: None,
                near_expiry: false,
                remaining_label: None,
            },
        ];
    let overrides_count = overrides.len();
    AgentDetailPage {
        id: "a1".into(),
        name: "claude-code".into(),
        agent_type: "attended".into(),
        profile_id: "p2".into(),
        profile_name: "Read Only".into(),
        created_at: "2026-04-01".into(),
        sessions: vec![
            AgentSessionRow {
                token_prefix: "mcp_tok_7f3a…".into(),
                created_at: "2026-05-04 13:41".into(),
                last_used: "2026-05-04 14:23 (2m ago)".into(),
                expires_at: "2026-05-04 21:41".into(),
            },
        ],
        overrides_count,
        overrides,
    }
}

pub fn integration_tools() -> IntegrationToolsPage {
    let tools = vec![
            IntegrationToolRow { local_name: "list_threads".into(), full_name: "gmail__list_threads".into(), description: Some("List email threads matching a query. Supports the full Gmail search syntax including operators such as from:, to:, subject:, has:attachment, is:unread, label:, after:, before:, and boolean operators. Returns thread IDs, snippet, label IDs, and message count. Paginated via nextPageToken.".into()), access_type: "read".into() },
            IntegrationToolRow { local_name: "get_thread".into(), full_name: "gmail__get_thread".into(), description: Some("Get a full email thread by thread ID including all messages, headers, body parts (text/plain and text/html), inline images, and attachment metadata. The format parameter controls how much of the payload is returned: full, metadata, minimal, or raw.".into()), access_type: "read".into() },
            IntegrationToolRow { local_name: "get_email".into(), full_name: "gmail__get_email".into(), description: Some("Get a single email message by message ID. Returns the full RFC 2822 message payload including all MIME parts. Use the format parameter to control response verbosity. Attachments are referenced by ID and must be fetched separately with get_attachment.".into()), access_type: "read".into() },
            IntegrationToolRow { local_name: "search".into(), full_name: "gmail__search".into(), description: Some("Search across all emails using Gmail query syntax. Returns matching thread or message IDs with snippets. Supports all Gmail search operators. Results are sorted by relevance by default; use the orderBy parameter to sort by date. Maximum 500 results per page.".into()), access_type: "read".into() },
            IntegrationToolRow { local_name: "list_labels".into(), full_name: "gmail__list_labels".into(), description: Some("List all Gmail labels for the authenticated account including system labels (INBOX, SENT, DRAFT, SPAM, TRASH) and user-created labels. Returns label ID, name, type, and visibility settings for message list and label list views.".into()), access_type: "read".into() },
            IntegrationToolRow { local_name: "get_attachment".into(), full_name: "gmail__get_attachment".into(), description: Some("Download an email attachment by message ID and attachment ID. Returns the attachment data as a base64url-encoded string. For large attachments the data may be returned as a URI instead. Attachment IDs are obtained from the parts array of a get_email or get_thread response.".into()), access_type: "read".into() },
            IntegrationToolRow { local_name: "list_drafts".into(), full_name: "gmail__list_drafts".into(), description: Some("List draft messages in the mailbox. Returns draft ID, message ID, and snippet. Supports the same query syntax as list_threads for filtering. Paginated via nextPageToken. Draft content is fetched via get_email using the message ID from the draft object.".into()), access_type: "read".into() },
            IntegrationToolRow { local_name: "send_email".into(), full_name: "gmail__send_email".into(), description: Some("Send an email message on behalf of the authenticated user. Accepts a raw RFC 2822 message encoded as base64url, or a structured message with to, cc, bcc, subject, body (text and/or HTML), and attachment references. Sent messages are automatically added to the SENT label. Returns the sent message ID and thread ID.".into()), access_type: "write".into() },
            IntegrationToolRow { local_name: "create_draft".into(), full_name: "gmail__create_draft".into(), description: Some("Create a new draft message without sending it. Accepts the same input format as send_email. The draft is saved to the DRAFTS label and can be retrieved, updated, or sent later. Returns the draft ID and message ID. Replaces an existing draft if a draft ID is provided.".into()), access_type: "write".into() },
            IntegrationToolRow { local_name: "delete_email".into(), full_name: "gmail__delete_email".into(), description: Some("Permanently and immediately delete an email message, bypassing the Trash folder. This action is irreversible and cannot be undone. The message is removed from all labels and is no longer accessible. To move to Trash instead (recoverable for 30 days), use the trash_email tool.".into()), access_type: "write".into() },
            IntegrationToolRow { local_name: "label_message".into(), full_name: "gmail__label_message".into(), description: Some("Apply or remove labels from one or more messages. Accepts arrays of label IDs to add and remove. Can be used to mark messages as read/unread (UNREAD label), star/unstar (STARRED label), archive (remove INBOX label), move to spam (add SPAM label), or apply custom user-created labels.".into()), access_type: "write".into() },
            IntegrationToolRow { local_name: "mark_read".into(), full_name: "gmail__mark_read".into(), description: Some("Mark one or more messages as read or unread by modifying the UNREAD system label. Accepts a list of message IDs and a boolean indicating the desired read state. This is a convenience wrapper around label_message that applies specifically to the UNREAD label.".into()), access_type: "write".into() },
        ];
    let tool_count = tools.len();
    IntegrationToolsPage {
        id: "1".into(),
        slug: "gmail".into(),
        name: "Gmail".into(),
        mcp_url: "https://gmail-mcp.example.com".into(),
        connected: true,
        tool_count,
        tools,
    }
}
