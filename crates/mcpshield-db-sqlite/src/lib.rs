use async_trait::async_trait;
use mcpshield_db::{
    AccessToken, AuthCode, ClientAuthInfo, ClientAuthorizeInfo, OAuthClient, PolicyRule, Store,
    StoreError, TokenLookup,
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
             (client_id, agent_id, client_secret_hash, client_name, redirect_uris, created_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&client.client_id)
        .bind(&client.agent_id)
        .bind(&client.client_secret_hash)
        .bind(&client.client_name)
        .bind(&redirect_uris_json)
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
        let rows: Vec<(String, String, String, String, String, i64)> = sqlx::query_as(
            "SELECT client_id, agent_id, client_secret_hash, client_name, redirect_uris, created_at \
             FROM oauth_clients ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(store_err)?;
        rows.into_iter()
            .map(|(client_id, agent_id, client_secret_hash, client_name, redirect_uris_json, created_at)| {
                let redirect_uris: Vec<String> =
                    serde_json::from_str(&redirect_uris_json).map_err(store_err)?;
                Ok(OAuthClient {
                    client_id,
                    agent_id,
                    client_secret_hash,
                    client_name,
                    redirect_uris,
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
        sqlx::query("DELETE FROM policy_rules WHERE agent_id = ?")
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
        let row: Option<(String, String)> = sqlx::query_as(
            "SELECT agent_id, client_id FROM access_tokens \
             WHERE token_hash = ? AND expires_at > ?",
        )
        .bind(token_hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(store_err)?;
        Ok(row.map(|(agent_id, client_id)| TokenLookup { agent_id, client_id }))
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
        let allowed_int: i64 = if rule.allowed { 1 } else { 0 };
        sqlx::query(
            "INSERT INTO policy_rules (agent_id, tool_name, allowed, created_at) \
             VALUES (?, ?, ?, ?) \
             ON CONFLICT(agent_id, tool_name) DO UPDATE SET allowed = excluded.allowed",
        )
        .bind(&rule.agent_id)
        .bind(&rule.tool_name)
        .bind(allowed_int)
        .bind(rule.created_at)
        .execute(&self.pool)
        .await
        .map_err(store_err)?;
        Ok(())
    }

    async fn delete_policy_rule(
        &self,
        agent_id: &str,
        tool_name: &str,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "DELETE FROM policy_rules WHERE agent_id = ? AND tool_name = ?",
        )
        .bind(agent_id)
        .bind(tool_name)
        .execute(&self.pool)
        .await
        .map_err(store_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_policy_rules(&self, agent_id: &str) -> Result<Vec<PolicyRule>, StoreError> {
        let rows: Vec<(String, String, i64, i64)> = sqlx::query_as(
            "SELECT agent_id, tool_name, allowed, created_at \
             FROM policy_rules WHERE agent_id = ? ORDER BY tool_name",
        )
        .bind(agent_id)
        .fetch_all(&self.pool)
        .await
        .map_err(store_err)?;
        Ok(rows
            .into_iter()
            .map(|(agent_id, tool_name, allowed, created_at)| PolicyRule {
                agent_id,
                tool_name,
                allowed: allowed != 0,
                created_at,
            })
            .collect())
    }

    async fn get_policy_rule(
        &self,
        agent_id: &str,
        tool_name: &str,
    ) -> Result<Option<PolicyRule>, StoreError> {
        let row: Option<(i64, i64)> = sqlx::query_as(
            "SELECT allowed, created_at FROM policy_rules \
             WHERE agent_id = ? AND tool_name = ?",
        )
        .bind(agent_id)
        .bind(tool_name)
        .fetch_optional(&self.pool)
        .await
        .map_err(store_err)?;
        Ok(row.map(|(allowed, created_at)| PolicyRule {
            agent_id: agent_id.to_string(),
            tool_name: tool_name.to_string(),
            allowed: allowed != 0,
            created_at,
        }))
    }
}
