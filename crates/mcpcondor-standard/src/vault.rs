use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use mcpcondor_core::error::CoreError;
use mcpcondor_core::vault::{VaultBackend, VaultTokenData};
use mcpcondor_db::{Store, VaultToken};
use ring::aead::{Aad, BoundKey, Nonce, NonceSequence, UnboundKey, AES_256_GCM};
use ring::error::Unspecified;
use ring::rand::{SecureRandom, SystemRandom};
use uuid::Uuid;

use crate::crypto::unix_timestamp_secs;

struct OnceSingleUseNonce([u8; 12]);

impl NonceSequence for OnceSingleUseNonce {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        Ok(Nonce::assume_unique_for_key(self.0))
    }
}

pub struct SqliteVaultBackend {
    store: Arc<dyn Store>,
    master_key: [u8; 32],
    rng: SystemRandom,
}

impl SqliteVaultBackend {
    pub fn new(store: Arc<dyn Store>, master_key: [u8; 32]) -> Self {
        Self { store, master_key, rng: SystemRandom::new() }
    }
}

impl VaultBackend for SqliteVaultBackend {
    fn store_token(
        &self,
        integration_id: &str,
        data: &VaultTokenData,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), CoreError>> + Send + '_>> {
        let integration_id = integration_id.to_string();
        // Extract all fields from `data` before entering the async block so the
        // future only borrows `&self` and not `data` (which has a shorter lifetime).
        let plaintext = match serde_json::to_vec(data) {
            Ok(p) => p,
            Err(e) => {
                return Box::pin(std::future::ready(Err(CoreError::Internal(e.to_string()))));
            }
        };
        let expires_at = data.expires_at;

        Box::pin(async move {
            let mut nonce_bytes = [0u8; 12];
            self.rng.fill(&mut nonce_bytes)
                .map_err(|_| CoreError::Internal("nonce generation failed".to_string()))?;

            let unbound = UnboundKey::new(&AES_256_GCM, &self.master_key)
                .map_err(|_| CoreError::Internal("key construction failed".to_string()))?;
            let mut sealing_key = ring::aead::SealingKey::new(
                unbound,
                OnceSingleUseNonce(nonce_bytes),
            );

            let mut in_out = plaintext;
            // AAD binds the ciphertext to this specific integration_id
            let aad = Aad::from(integration_id.as_bytes());
            sealing_key
                .seal_in_place_append_tag(aad, &mut in_out)
                .map_err(|_| CoreError::Internal("encryption failed".to_string()))?;

            let token = VaultToken {
                id: Uuid::new_v4().to_string(),
                integration_id: integration_id.clone(),
                nonce: nonce_bytes.to_vec(),
                ciphertext: in_out,
                expires_at,
                created_at: unix_timestamp_secs(),
            };
            self.store.upsert_vault_token(&token).await
                .map_err(|e| CoreError::Internal(e.to_string()))
        })
    }

    fn get_token(
        &self,
        integration_id: &str,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<Option<VaultTokenData>, CoreError>> + Send + '_>> {
        let integration_id = integration_id.to_string();
        Box::pin(async move {
            let record = self.store.get_vault_token(&integration_id).await
                .map_err(|e| CoreError::Internal(e.to_string()))?;

            let record = match record {
                Some(r) => r,
                None => return Ok(None),
            };

            let nonce_bytes: [u8; 12] = record.nonce.as_slice().try_into()
                .map_err(|_| CoreError::Internal("invalid nonce length".to_string()))?;

            let unbound = UnboundKey::new(&AES_256_GCM, &self.master_key)
                .map_err(|_| CoreError::Internal("key construction failed".to_string()))?;
            let mut opening_key = ring::aead::OpeningKey::new(
                unbound,
                OnceSingleUseNonce(nonce_bytes),
            );

            let mut ciphertext = record.ciphertext;
            let aad = Aad::from(integration_id.as_bytes());
            let plaintext = opening_key
                .open_in_place(aad, &mut ciphertext)
                .map_err(|_| CoreError::Internal("decryption failed".to_string()))?;

            let data: VaultTokenData = serde_json::from_slice(plaintext)
                .map_err(|e| CoreError::Internal(e.to_string()))?;
            Ok(Some(data))
        })
    }

    fn delete_token(
        &self,
        integration_id: &str,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), CoreError>> + Send + '_>> {
        let integration_id = integration_id.to_string();
        Box::pin(async move {
            self.store.delete_vault_token(&integration_id).await
                .map_err(|e| CoreError::Internal(e.to_string()))?;
            Ok(())
        })
    }
}

/// Load or create the 32-byte vault master key.
/// Checks MCPSHIELD_VAULT_KEY env var first; otherwise uses/creates {data_dir}/vault.key.
pub fn load_or_create_vault_key(data_dir: &Path) -> anyhow::Result<[u8; 32]> {
    if let Ok(hex_val) = std::env::var("MCPSHIELD_VAULT_KEY") {
        let bytes = hex::decode(hex_val.trim())
            .map_err(|e| anyhow::anyhow!("MCPSHIELD_VAULT_KEY: invalid hex: {e}"))?;
        if bytes.len() != 32 {
            anyhow::bail!("MCPSHIELD_VAULT_KEY must be exactly 32 bytes (64 hex chars), got {}", bytes.len());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        return Ok(key);
    }

    let key_path = data_dir.join("vault.key");
    if key_path.exists() {
        let hex_str = std::fs::read_to_string(&key_path)
            .map_err(|e| anyhow::anyhow!("read vault.key: {e}"))?;
        let bytes = hex::decode(hex_str.trim())
            .map_err(|e| anyhow::anyhow!("vault.key: invalid hex: {e}"))?;
        if bytes.len() != 32 {
            anyhow::bail!("vault.key must be exactly 32 bytes (64 hex chars), got {}", bytes.len());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        return Ok(key);
    }

    // Generate a new key and persist it
    let rng = SystemRandom::new();
    let mut key_bytes = [0u8; 32];
    rng.fill(&mut key_bytes)
        .map_err(|_| anyhow::anyhow!("failed to generate vault key"))?;
    let hex_str = hex::encode(&key_bytes);

    write_key_file(&key_path, &hex_str)?;

    Ok(key_bytes)
}

#[cfg(unix)]
fn write_key_file(path: &Path, content: &str) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| anyhow::anyhow!("create vault.key: {e}"))?;
    file.write_all(content.as_bytes())
        .map_err(|e| anyhow::anyhow!("write vault.key: {e}"))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_key_file(path: &Path, content: &str) -> anyhow::Result<()> {
    std::fs::write(path, content.as_bytes())
        .map_err(|e| anyhow::anyhow!("write vault.key: {e}"))?;
    Ok(())
}
