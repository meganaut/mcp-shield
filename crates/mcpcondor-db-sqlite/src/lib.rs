use async_trait::async_trait;
use mcpcondor_db::{
    AccessToken, AgentOverride, AgentOverrideKind, AuditEventRow, AuthCode, ClientAuthInfo,
    ClientAuthorizeInfo, GlobalRule, Integration, OAuthClient, PolicyRule, Profile, ProfileRule,
    Store, StoreError, TokenLookup, VaultToken,
};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::str::FromStr;

pub struct SqliteStore {
    pool: SqlitePool,
}

impl SqliteStore {
    pub async fn open(path: &str) -> anyhow::Result<Self> {
        let url = if path == ":memory:" {
            "sqlite::memory:".to_string()
        } else {
            format!("sqlite://{}?mode=rwc", path)
        };
        // foreign_keys must be set per-connection via ConnectOptions, not as a
        // post-connect PRAGMA execute, because sqlx creates connections lazily
        // and only the connection that runs a plain PRAGMA would have it applied.
        // journal_mode=WAL is a database-level setting (persisted in file header)
        // so it only needs to run once, but setting it here via options is fine.
        let opts = SqliteConnectOptions::from_str(&url)?
            .journal_mode(SqliteJournalMode::Wal)
            .pragma("foreign_keys", "on");
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(opts)
            .await?;
        Ok(Self { pool })
    }
}

fn store_err(e: impl std::fmt::Display) -> StoreError {
    StoreError::Internal(e.to_string())
}

fn store_err_db(e: sqlx::Error) -> StoreError {
    if let sqlx::Error::Database(ref db_err) = e {
        if db_err.is_unique_violation() {
            return StoreError::Conflict(db_err.message().to_string());
        }
    }
    StoreError::Internal(e.to_string())
}

#[async_trait]
impl Store for SqliteStore {
    async fn run_migrations(&self) -> Result<(), StoreError> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(store_err)
    }

    async fn is_setup_complete(&self) -> Result<bool, StoreError> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT value FROM setup_state WHERE key = 'setup_complete'")
                .fetch_optional(&self.pool)
                .await
                .map_err(store_err)?;
        Ok(row.map(|r| r.0 == "1").unwrap_or(false))
    }

    async fn complete_setup(
        &self,
        admin_username: &str,
        admin_password_hash: &str,
        issuer_url: &str,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(store_err)?;
        for (key, val) in [
            ("admin_username", admin_username),
            ("admin_password_hash", admin_password_hash),
            ("issuer_url", issuer_url),
            ("setup_complete", "1"),
        ] {
            sqlx::query(
                "INSERT OR REPLACE INTO setup_state (key, value) VALUES (?, ?)",
            )
            .bind(key)
            .bind(val)
            .execute(&mut *tx)
            .await
            .map_err(store_err)?;
        }
        tx.commit().await.map_err(store_err)
    }

    async fn get_setup_value(&self, key: &str) -> Result<Option<String>, StoreError> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT value FROM setup_state WHERE key = ?")
                .bind(key)
                .fetch_optional(&self.pool)
                .await
                .map_err(store_err)?;
        Ok(row.map(|r| r.0))
    }

    async fn insert_oauth_client(&self, client: &OAuthClient) -> Result<(), StoreError> {
        let redirect_uris_json =
            serde_json::to_string(&client.redirect_uris).map_err(store_err)?;
        sqlx::query(
            "INSERT INTO oauth_clients \
             (client_id, agent_id, client_secret_hash, client_name, redirect_uris, profile_id, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&client.client_id)
        .bind(&client.agent_id)
        .bind(&client.client_secret_hash)
        .bind(&client.client_name)
        .bind(&redirect_uris_json)
        .bind(&client.profile_id)
        .bind(client.created_at)
        .execute(&self.pool)
        .await
        .map_err(store_err_db)?;
        Ok(())
    }

    async fn get_client_auth_info(
        &self,
        client_id: &str,
    ) -> Result<Option<ClientAuthInfo>, StoreError> {
        let row: Option<(String, String)> = sqlx::query_as(
            "SELECT client_secret_hash, agent_id FROM oauth_clients WHERE client_id = ?",
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(store_err)?;
        Ok(row.map(|(client_secret_hash, agent_id)| ClientAuthInfo {
            client_secret_hash,
            agent_id,
        }))
    }

    async fn get_client_authorize_info(
        &self,
        client_id: &str,
    ) -> Result<Option<ClientAuthorizeInfo>, StoreError> {
        let row: Option<(String, String, String)> = sqlx::query_as(
            "SELECT agent_id, redirect_uris, client_name FROM oauth_clients WHERE client_id = ?",
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(store_err)?;
        match row {
            None => Ok(None),
            Some((agent_id, redirect_uris_json, client_name)) => {
                let redirect_uris: Vec<String> =
                    serde_json::from_str(&redirect_uris_json).map_err(store_err)?;
                Ok(Some(ClientAuthorizeInfo {
                    agent_id,
                    redirect_uris,
                    client_name,
                }))
            }
        }
    }

    async fn get_client_name(&self, client_id: &str) -> Result<Option<String>, StoreError> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT client_name FROM oauth_clients WHERE client_id = ?")
                .bind(client_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(store_err)?;
        Ok(row.map(|r| r.0))
    }

    async fn list_oauth_clients(&self) -> Result<Vec<OAuthClient>, StoreError> {
        let rows: Vec<(String, String, String, String, String, Option<String>, i64)> = sqlx::query_as(
            "SELECT client_id, agent_id, client_secret_hash, client_name, redirect_uris, profile_id, created_at \
             FROM oauth_clients ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(store_err)?;
        rows.into_iter()
            .map(|(client_id, agent_id, client_secret_hash, client_name, redirect_uris_json, profile_id, created_at)| {
                let redirect_uris: Vec<String> =
                    serde_json::from_str(&redirect_uris_json).map_err(store_err)?;
                Ok(OAuthClient {
                    client_id,
                    agent_id,
                    client_secret_hash,
                    client_name,
                    redirect_uris,
                    profile_id,
                    created_at,
                })
            })
            .collect()
    }

    async fn delete_oauth_client(&self, agent_id: &str) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await.map_err(store_err)?;

        // Find client_id for this agent_id
        let row: Option<(String,)> =
            sqlx::query_as("SELECT client_id FROM oauth_clients WHERE agent_id = ?")
                .bind(agent_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(store_err)?;

        let client_id = match row {
            Some((id,)) => id,
            None => return Ok(false),
        };

        // Delete all dependent records (no ON DELETE CASCADE in current schema)
        sqlx::query("DELETE FROM access_tokens WHERE client_id = ?")
            .bind(&client_id)
            .execute(&mut *tx)
            .await
            .map_err(store_err)?;
        sqlx::query("DELETE FROM auth_codes WHERE client_id = ?")
            .bind(&client_id)
            .execute(&mut *tx)
            .await
            .map_err(store_err)?;
        sqlx::query("DELETE FROM agent_overrides WHERE agent_id = ?")
            .bind(agent_id)
            .execute(&mut *tx)
            .await
            .map_err(store_err)?;
        sqlx::query("DELETE FROM oauth_clients WHERE client_id = ?")
            .bind(&client_id)
            .execute(&mut *tx)
            .await
            .map_err(store_err)?;

        tx.commit().await.map_err(store_err)?;
        Ok(true)
    }

    async fn insert_auth_code(&self, code: &AuthCode) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO auth_codes \
             (code, client_id, redirect_uri, code_challenge, agent_id, expires_at, used) \
             VALUES (?, ?, ?, ?, ?, ?, 0)",
        )
        .bind(&code.code)
        .bind(&code.client_id)
        .bind(&code.redirect_uri)
        .bind(&code.code_challenge)
        .bind(&code.agent_id)
        .bind(code.expires_at)
        .execute(&self.pool)
        .await
        .map_err(store_err_db)?;
        Ok(())
    }

    async fn get_auth_code(
        &self,
        code: &str,
        client_id: &str,
        now: i64,
    ) -> Result<Option<AuthCode>, StoreError> {
        let row: Option<(String, String, String, String, String, i64, i64)> = sqlx::query_as(
            "SELECT code, client_id, redirect_uri, code_challenge, agent_id, expires_at, used \
             FROM auth_codes \
             WHERE code = ? AND client_id = ? AND used = 0 AND expires_at > ?",
        )
        .bind(code)
        .bind(client_id)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(store_err)?;
        Ok(row.map(|(code, client_id, redirect_uri, code_challenge, agent_id, expires_at, used)| {
            AuthCode {
                code,
                client_id,
                redirect_uri,
                code_challenge,
                agent_id,
                expires_at,
                used: used != 0,
            }
        }))
    }

    async fn mark_auth_code_used(&self, code: &str, now: i64) -> Result<bool, StoreError> {
        // Also re-validates expiry atomically so the cleanup job can't race with token exchange.
        let result = sqlx::query(
            "UPDATE auth_codes SET used = 1 WHERE code = ? AND used = 0 AND expires_at > ?",
        )
        .bind(code)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(store_err)?;
        Ok(result.rows_affected() == 1)
    }

    async fn delete_expired_auth_codes(&self, now: i64) -> Result<u64, StoreError> {
        let result = sqlx::query("DELETE FROM auth_codes WHERE expires_at < ?")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(store_err)?;
        Ok(result.rows_affected())
    }

    async fn delete_agent_tokens(&self, agent_id: &str) -> Result<u64, StoreError> {
        let result = sqlx::query("DELETE FROM access_tokens WHERE agent_id = ?")
            .bind(agent_id)
            .execute(&self.pool)
            .await
            .map_err(store_err)?;
        Ok(result.rows_affected())
    }

    async fn insert_audit_event(&self, event: &AuditEventRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO audit_events \
             (id, timestamp_ms, agent_id, operation_name, outcome, latency_ms, \
              integration_slug, deny_reason, error_message, client_id, dlp_detections) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&event.id)
        .bind(event.timestamp_ms)
        .bind(&event.agent_id)
        .bind(&event.operation_name)
        .bind(&event.outcome)
        .bind(event.latency_ms)
        .bind(&event.integration_slug)
        .bind(&event.deny_reason)
        .bind(&event.error_message)
        .bind(&event.client_id)
        .bind(&event.dlp_detections)
        .execute(&self.pool)
        .await
        .map_err(store_err)?;
        Ok(())
    }

    async fn list_audit_events(
        &self,
        agent_id: &str,
        limit: i64,
    ) -> Result<Vec<AuditEventRow>, StoreError> {
        type Row = (String, i64, String, String, String, i64, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>);
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT id, timestamp_ms, agent_id, operation_name, outcome, latency_ms, \
              integration_slug, deny_reason, error_message, client_id, dlp_detections \
             FROM audit_events WHERE agent_id = ? ORDER BY timestamp_ms DESC LIMIT ?",
        )
        .bind(agent_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(store_err)?;
        Ok(rows
            .into_iter()
            .map(|(id, timestamp_ms, agent_id, operation_name, outcome, latency_ms,
                   integration_slug, deny_reason, error_message, client_id, dlp_detections)| {
                AuditEventRow {
                    id, timestamp_ms, agent_id, operation_name, outcome, latency_ms,
                    integration_slug, deny_reason, error_message, client_id, dlp_detections,
                }
            })
            .collect())
    }

    async fn delete_old_audit_events(&self, before_ms: i64) -> Result<u64, StoreError> {
        let result = sqlx::query("DELETE FROM audit_events WHERE timestamp_ms < ?")
            .bind(before_ms)
            .execute(&self.pool)
            .await
            .map_err(store_err)?;
        Ok(result.rows_affected())
    }

    async fn list_all_audit_events(&self, limit: i64) -> Result<Vec<AuditEventRow>, StoreError> {
        type Row = (String, i64, String, String, String, i64, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>);
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT id, timestamp_ms, agent_id, operation_name, outcome, latency_ms, \
              integration_slug, deny_reason, error_message, client_id, dlp_detections \
             FROM audit_events ORDER BY timestamp_ms DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(store_err)?;
        Ok(rows.into_iter().map(|(id, timestamp_ms, agent_id, operation_name, outcome, latency_ms,
                integration_slug, deny_reason, error_message, client_id, dlp_detections)| {
            AuditEventRow {
                id, timestamp_ms, agent_id, operation_name, outcome, latency_ms,
                integration_slug, deny_reason, error_message, client_id, dlp_detections,
            }
        }).collect())
    }

    async fn count_audit_events_since(&self, since_ms: i64) -> Result<(u64, u64), StoreError> {
        let row: (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*), SUM(CASE WHEN outcome LIKE 'denied:%' THEN 1 ELSE 0 END) \
             FROM audit_events WHERE timestamp_ms >= ?",
        )
        .bind(since_ms)
        .fetch_one(&self.pool)
        .await
        .map_err(store_err)?;
        Ok((row.0 as u64, row.1 as u64))
    }

    async fn insert_access_token(&self, token: &AccessToken) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO access_tokens \
             (token_hash, client_id, agent_id, expires_at, created_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&token.token_hash)
        .bind(&token.client_id)
        .bind(&token.agent_id)
        .bind(token.expires_at)
        .bind(token.created_at)
        .execute(&self.pool)
        .await
        .map_err(store_err)?;
        Ok(())
    }

    async fn get_token_by_hash(
        &self,
        token_hash: &str,
        now: i64,
    ) -> Result<Option<TokenLookup>, StoreError> {
        let row: Option<(String, String, i64)> = sqlx::query_as(
            "SELECT agent_id, client_id, expires_at FROM access_tokens \
             WHERE token_hash = ? AND expires_at > ?",
        )
        .bind(token_hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(store_err)?;
        Ok(row.map(|(agent_id, client_id, expires_at)| TokenLookup { agent_id, client_id, expires_at }))
    }

    async fn delete_expired_access_tokens(&self, now: i64) -> Result<u64, StoreError> {
        let result = sqlx::query("DELETE FROM access_tokens WHERE expires_at < ?")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(store_err)?;
        Ok(result.rows_affected())
    }

    async fn upsert_policy_rule(&self, rule: &PolicyRule) -> Result<(), StoreError> {
        // Delegate to agent_overrides (policy_rules table removed in migration 0009)
        let override_ = AgentOverride {
            agent_id: rule.agent_id.clone(),
            tool_name: rule.tool_name.clone(),
            allowed: rule.allowed,
            kind: AgentOverrideKind::Static,
            created_at: rule.created_at,
        };
        self.upsert_agent_override(&override_).await
    }

    async fn delete_policy_rule(
        &self,
        agent_id: &str,
        tool_name: &str,
    ) -> Result<bool, StoreError> {
        self.delete_agent_override(agent_id, tool_name).await
    }

    async fn list_policy_rules(&self, agent_id: &str) -> Result<Vec<PolicyRule>, StoreError> {
        let overrides = self.list_agent_overrides(agent_id).await?;
        Ok(overrides
            .into_iter()
            .map(|o| PolicyRule {
                agent_id: o.agent_id,
                tool_name: o.tool_name,
                allowed: o.allowed,
                created_at: o.created_at,
            })
            .collect())
    }

    async fn get_policy_rule(
        &self,
        agent_id: &str,
        tool_name: &str,
    ) -> Result<Option<PolicyRule>, StoreError> {
        let override_ = self.get_agent_override(agent_id, tool_name).await?;
        Ok(override_.map(|o| PolicyRule {
            agent_id: o.agent_id,
            tool_name: o.tool_name,
            allowed: o.allowed,
            created_at: o.created_at,
        }))
    }

    async fn insert_integration(&self, integration: &Integration) -> Result<(), StoreError> {
        let scopes_json = match &integration.oauth_scopes {
            Some(s) => Some(serde_json::to_string(s).map_err(store_err)?),
            None => None,
        };
        let connected: i64 = if integration.connected { 1 } else { 0 };
        let default_stance: i64 = if integration.default_stance { 1 } else { 0 };
        sqlx::query(
            "INSERT INTO integrations \
             (id, slug, name, mcp_url, oauth_auth_url, oauth_token_url, oauth_client_id, oauth_scopes, connected, default_stance, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&integration.id)
        .bind(&integration.slug)
        .bind(&integration.name)
        .bind(&integration.mcp_url)
        .bind(&integration.oauth_auth_url)
        .bind(&integration.oauth_token_url)
        .bind(&integration.oauth_client_id)
        .bind(&scopes_json)
        .bind(connected)
        .bind(default_stance)
        .bind(integration.created_at)
        .execute(&self.pool)
        .await
        .map_err(store_err_db)?;
        Ok(())
    }

    async fn get_integration(&self, id: &str) -> Result<Option<Integration>, StoreError> {
        let row: Option<(String, String, String, String, Option<String>, Option<String>, Option<String>, Option<String>, i64, i64, i64)> =
            sqlx::query_as(
                "SELECT id, slug, name, mcp_url, oauth_auth_url, oauth_token_url, oauth_client_id, oauth_scopes, connected, default_stance, created_at \
                 FROM integrations WHERE id = ?",
            )
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(store_err)?;
        row.map(|r| parse_integration_row(r)).transpose()
    }

    async fn get_integration_by_slug(&self, slug: &str) -> Result<Option<Integration>, StoreError> {
        let row: Option<(String, String, String, String, Option<String>, Option<String>, Option<String>, Option<String>, i64, i64, i64)> =
            sqlx::query_as(
                "SELECT id, slug, name, mcp_url, oauth_auth_url, oauth_token_url, oauth_client_id, oauth_scopes, connected, default_stance, created_at \
                 FROM integrations WHERE slug = ?",
            )
            .bind(slug)
            .fetch_optional(&self.pool)
            .await
            .map_err(store_err)?;
        row.map(|r| parse_integration_row(r)).transpose()
    }

    async fn list_integrations(&self) -> Result<Vec<Integration>, StoreError> {
        let rows: Vec<(String, String, String, String, Option<String>, Option<String>, Option<String>, Option<String>, i64, i64, i64)> =
            sqlx::query_as(
                "SELECT id, slug, name, mcp_url, oauth_auth_url, oauth_token_url, oauth_client_id, oauth_scopes, connected, default_stance, created_at \
                 FROM integrations ORDER BY created_at DESC",
            )
            .fetch_all(&self.pool)
            .await
            .map_err(store_err)?;
        rows.into_iter().map(|r| parse_integration_row(r)).collect()
    }

    async fn update_integration_connected(&self, id: &str, connected: bool) -> Result<(), StoreError> {
        let connected_int: i64 = if connected { 1 } else { 0 };
        sqlx::query("UPDATE integrations SET connected = ? WHERE id = ?")
            .bind(connected_int)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(store_err)?;
        Ok(())
    }

    async fn delete_integration(&self, id: &str) -> Result<bool, StoreError> {
        let result = sqlx::query("DELETE FROM integrations WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(store_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn upsert_vault_token(&self, token: &VaultToken) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT OR REPLACE INTO vault_tokens \
             (id, integration_id, nonce, ciphertext, expires_at, created_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&token.id)
        .bind(&token.integration_id)
        .bind(&token.nonce)
        .bind(&token.ciphertext)
        .bind(token.expires_at)
        .bind(token.created_at)
        .execute(&self.pool)
        .await
        .map_err(store_err)?;
        Ok(())
    }

    async fn get_vault_token(&self, integration_id: &str) -> Result<Option<VaultToken>, StoreError> {
        let row: Option<(String, String, Vec<u8>, Vec<u8>, Option<i64>, i64)> = sqlx::query_as(
            "SELECT id, integration_id, nonce, ciphertext, expires_at, created_at \
             FROM vault_tokens WHERE integration_id = ?",
        )
        .bind(integration_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(store_err)?;
        Ok(row.map(|(id, integration_id, nonce, ciphertext, expires_at, created_at)| {
            VaultToken { id, integration_id, nonce, ciphertext, expires_at, created_at }
        }))
    }

    async fn delete_vault_token(&self, integration_id: &str) -> Result<bool, StoreError> {
        let result = sqlx::query("DELETE FROM vault_tokens WHERE integration_id = ?")
            .bind(integration_id)
            .execute(&self.pool)
            .await
            .map_err(store_err)?;
        Ok(result.rows_affected() > 0)
    }

    // --- Profiles ---

    async fn insert_profile(&self, profile: &Profile) -> Result<(), StoreError> {
        let is_default: i64 = if profile.is_default { 1 } else { 0 };
        sqlx::query(
            "INSERT INTO profiles (id, name, description, is_default, created_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&profile.id)
        .bind(&profile.name)
        .bind(&profile.description)
        .bind(is_default)
        .bind(profile.created_at)
        .execute(&self.pool)
        .await
        .map_err(store_err_db)?;
        Ok(())
    }

    async fn get_profile(&self, id: &str) -> Result<Option<Profile>, StoreError> {
        let row: Option<(String, String, Option<String>, i64, i64)> = sqlx::query_as(
            "SELECT id, name, description, is_default, created_at FROM profiles WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(store_err)?;
        Ok(row.map(|(id, name, description, is_default, created_at)| Profile {
            id,
            name,
            description,
            is_default: is_default != 0,
            created_at,
        }))
    }

    async fn list_profiles(&self) -> Result<Vec<Profile>, StoreError> {
        let rows: Vec<(String, String, Option<String>, i64, i64)> = sqlx::query_as(
            "SELECT id, name, description, is_default, created_at FROM profiles ORDER BY created_at ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(store_err)?;
        Ok(rows
            .into_iter()
            .map(|(id, name, description, is_default, created_at)| Profile {
                id,
                name,
                description,
                is_default: is_default != 0,
                created_at,
            })
            .collect())
    }

    async fn update_profile(&self, id: &str, name: &str, description: Option<&str>) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE profiles SET name = ?, description = ? WHERE id = ?",
        )
        .bind(name)
        .bind(description)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(store_err)?;
        Ok(())
    }

    async fn delete_profile(&self, id: &str) -> Result<bool, StoreError> {
        let result = sqlx::query("DELETE FROM profiles WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(store_err)?;
        Ok(result.rows_affected() > 0)
    }

    // --- Profile rules ---

    async fn upsert_profile_rule(&self, rule: &ProfileRule) -> Result<(), StoreError> {
        let allowed: i64 = if rule.allowed { 1 } else { 0 };
        sqlx::query(
            "INSERT INTO profile_rules (profile_id, tool_name, allowed, created_at) \
             VALUES (?, ?, ?, ?) \
             ON CONFLICT(profile_id, tool_name) DO UPDATE SET allowed = excluded.allowed",
        )
        .bind(&rule.profile_id)
        .bind(&rule.tool_name)
        .bind(allowed)
        .bind(rule.created_at)
        .execute(&self.pool)
        .await
        .map_err(store_err)?;
        Ok(())
    }

    async fn delete_profile_rule(&self, profile_id: &str, tool_name: &str) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "DELETE FROM profile_rules WHERE profile_id = ? AND tool_name = ?",
        )
        .bind(profile_id)
        .bind(tool_name)
        .execute(&self.pool)
        .await
        .map_err(store_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_profile_rules(&self, profile_id: &str) -> Result<Vec<ProfileRule>, StoreError> {
        let rows: Vec<(String, String, i64, i64)> = sqlx::query_as(
            "SELECT profile_id, tool_name, allowed, created_at \
             FROM profile_rules WHERE profile_id = ? ORDER BY tool_name",
        )
        .bind(profile_id)
        .fetch_all(&self.pool)
        .await
        .map_err(store_err)?;
        Ok(rows
            .into_iter()
            .map(|(profile_id, tool_name, allowed, created_at)| ProfileRule {
                profile_id,
                tool_name,
                allowed: allowed != 0,
                created_at,
            })
            .collect())
    }

    async fn get_profile_rule(&self, profile_id: &str, tool_name: &str) -> Result<Option<ProfileRule>, StoreError> {
        let row: Option<(i64, i64)> = sqlx::query_as(
            "SELECT allowed, created_at FROM profile_rules WHERE profile_id = ? AND tool_name = ?",
        )
        .bind(profile_id)
        .bind(tool_name)
        .fetch_optional(&self.pool)
        .await
        .map_err(store_err)?;
        Ok(row.map(|(allowed, created_at)| ProfileRule {
            profile_id: profile_id.to_string(),
            tool_name: tool_name.to_string(),
            allowed: allowed != 0,
            created_at,
        }))
    }

    async fn set_profile_rules_for_integration(
        &self,
        profile_id: &str,
        tool_names: &[String],
        allowed: bool,
        now: i64,
    ) -> Result<(), StoreError> {
        let allowed_int: i64 = if allowed { 1 } else { 0 };
        let mut tx = self.pool.begin().await.map_err(store_err)?;
        for tool_name in tool_names {
            sqlx::query(
                "INSERT OR REPLACE INTO profile_rules (profile_id, tool_name, allowed, created_at) \
                 VALUES (?, ?, ?, ?)",
            )
            .bind(profile_id)
            .bind(tool_name)
            .bind(allowed_int)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(store_err)?;
        }
        tx.commit().await.map_err(store_err)
    }

    // --- Global rules ---

    async fn upsert_global_rule(&self, rule: &GlobalRule) -> Result<(), StoreError> {
        let allowed: i64 = if rule.allowed { 1 } else { 0 };
        sqlx::query(
            "INSERT INTO global_rules (tool_name, allowed, created_at) \
             VALUES (?, ?, ?) \
             ON CONFLICT(tool_name) DO UPDATE SET allowed = excluded.allowed",
        )
        .bind(&rule.tool_name)
        .bind(allowed)
        .bind(rule.created_at)
        .execute(&self.pool)
        .await
        .map_err(store_err)?;
        Ok(())
    }

    async fn delete_global_rule(&self, tool_name: &str) -> Result<bool, StoreError> {
        let result = sqlx::query("DELETE FROM global_rules WHERE tool_name = ?")
            .bind(tool_name)
            .execute(&self.pool)
            .await
            .map_err(store_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_global_rules(&self) -> Result<Vec<GlobalRule>, StoreError> {
        let rows: Vec<(String, i64, i64)> = sqlx::query_as(
            "SELECT tool_name, allowed, created_at FROM global_rules ORDER BY tool_name",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(store_err)?;
        Ok(rows
            .into_iter()
            .map(|(tool_name, allowed, created_at)| GlobalRule {
                tool_name,
                allowed: allowed != 0,
                created_at,
            })
            .collect())
    }

    async fn get_global_rule(&self, tool_name: &str) -> Result<Option<GlobalRule>, StoreError> {
        let row: Option<(i64, i64)> = sqlx::query_as(
            "SELECT allowed, created_at FROM global_rules WHERE tool_name = ?",
        )
        .bind(tool_name)
        .fetch_optional(&self.pool)
        .await
        .map_err(store_err)?;
        Ok(row.map(|(allowed, created_at)| GlobalRule {
            tool_name: tool_name.to_string(),
            allowed: allowed != 0,
            created_at,
        }))
    }

    // --- Agent overrides ---

    async fn upsert_agent_override(&self, override_: &AgentOverride) -> Result<(), StoreError> {
        let allowed: i64 = if override_.allowed { 1 } else { 0 };
        let (kind_str, expires_at, remaining) = match &override_.kind {
            AgentOverrideKind::Static => ("static", None::<i64>, None::<i64>),
            AgentOverrideKind::Until { expires_at } => ("until", Some(*expires_at), None),
            AgentOverrideKind::Uses { remaining } => ("uses", None, Some(*remaining)),
        };
        sqlx::query(
            "INSERT INTO agent_overrides (agent_id, tool_name, allowed, kind, expires_at, remaining, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(agent_id, tool_name) DO UPDATE SET \
               allowed = excluded.allowed, \
               kind = excluded.kind, \
               expires_at = excluded.expires_at, \
               remaining = excluded.remaining",
        )
        .bind(&override_.agent_id)
        .bind(&override_.tool_name)
        .bind(allowed)
        .bind(kind_str)
        .bind(expires_at)
        .bind(remaining)
        .bind(override_.created_at)
        .execute(&self.pool)
        .await
        .map_err(store_err)?;
        Ok(())
    }

    async fn delete_agent_override(&self, agent_id: &str, tool_name: &str) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "DELETE FROM agent_overrides WHERE agent_id = ? AND tool_name = ?",
        )
        .bind(agent_id)
        .bind(tool_name)
        .execute(&self.pool)
        .await
        .map_err(store_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_agent_overrides(&self, agent_id: &str) -> Result<Vec<AgentOverride>, StoreError> {
        let rows: Vec<(String, String, i64, String, Option<i64>, Option<i64>, i64)> = sqlx::query_as(
            "SELECT agent_id, tool_name, allowed, kind, expires_at, remaining, created_at \
             FROM agent_overrides WHERE agent_id = ? ORDER BY tool_name",
        )
        .bind(agent_id)
        .fetch_all(&self.pool)
        .await
        .map_err(store_err)?;
        rows.into_iter()
            .map(|(agent_id, tool_name, allowed, kind, expires_at, remaining, created_at)| {
                let kind = parse_override_kind(&kind, expires_at, remaining)?;
                Ok(AgentOverride {
                    agent_id,
                    tool_name,
                    allowed: allowed != 0,
                    kind,
                    created_at,
                })
            })
            .collect()
    }

    async fn get_agent_override(&self, agent_id: &str, tool_name: &str) -> Result<Option<AgentOverride>, StoreError> {
        let row: Option<(i64, String, Option<i64>, Option<i64>, i64)> = sqlx::query_as(
            "SELECT allowed, kind, expires_at, remaining, created_at \
             FROM agent_overrides WHERE agent_id = ? AND tool_name = ?",
        )
        .bind(agent_id)
        .bind(tool_name)
        .fetch_optional(&self.pool)
        .await
        .map_err(store_err)?;
        match row {
            None => Ok(None),
            Some((allowed, kind, expires_at, remaining, created_at)) => {
                let kind = parse_override_kind(&kind, expires_at, remaining)?;
                Ok(Some(AgentOverride {
                    agent_id: agent_id.to_string(),
                    tool_name: tool_name.to_string(),
                    allowed: allowed != 0,
                    kind,
                    created_at,
                }))
            }
        }
    }

    // --- Profile assignment ---

    async fn set_agent_profile(&self, agent_id: &str, profile_id: Option<&str>) -> Result<(), StoreError> {
        sqlx::query("UPDATE oauth_clients SET profile_id = ? WHERE agent_id = ?")
            .bind(profile_id)
            .bind(agent_id)
            .execute(&self.pool)
            .await
            .map_err(store_err)?;
        Ok(())
    }

    async fn get_agent_profile_id(&self, agent_id: &str) -> Result<Option<String>, StoreError> {
        let row: Option<(Option<String>,)> =
            sqlx::query_as("SELECT profile_id FROM oauth_clients WHERE agent_id = ?")
                .bind(agent_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(store_err)?;
        Ok(row.and_then(|(pid,)| pid))
    }
}

fn parse_override_kind(kind: &str, expires_at: Option<i64>, remaining: Option<i64>) -> Result<AgentOverrideKind, StoreError> {
    match kind {
        "static" => Ok(AgentOverrideKind::Static),
        "until" => {
            let expires_at = expires_at.ok_or_else(|| {
                StoreError::Internal("agent_override kind='until' missing expires_at".to_string())
            })?;
            Ok(AgentOverrideKind::Until { expires_at })
        }
        "uses" => {
            let remaining = remaining.ok_or_else(|| {
                StoreError::Internal("agent_override kind='uses' missing remaining".to_string())
            })?;
            Ok(AgentOverrideKind::Uses { remaining })
        }
        other => Err(StoreError::Internal(format!("unknown agent_override kind: {other}"))),
    }
}

fn parse_integration_row(
    row: (String, String, String, String, Option<String>, Option<String>, Option<String>, Option<String>, i64, i64, i64),
) -> Result<Integration, StoreError> {
    let (id, slug, name, mcp_url, oauth_auth_url, oauth_token_url, oauth_client_id, oauth_scopes_json, connected, default_stance, created_at) = row;
    let oauth_scopes = match oauth_scopes_json {
        Some(json) => Some(serde_json::from_str::<Vec<String>>(&json).map_err(store_err)?),
        None => None,
    };
    Ok(Integration {
        id,
        slug,
        name,
        mcp_url,
        oauth_auth_url,
        oauth_token_url,
        oauth_client_id,
        oauth_scopes,
        connected: connected != 0,
        default_stance: default_stance != 0,
        created_at,
    })
}
