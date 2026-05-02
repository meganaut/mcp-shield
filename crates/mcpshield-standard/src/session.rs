use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

const SESSION_TTL: Duration = Duration::from_secs(86400); // 24 hours
const MAX_SESSIONS: usize = 1000;

#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    // TODO M2: add agent_id and per-session downstream routing info here
    pub created_at: Instant,
}

pub type SessionStore = Arc<DashMap<String, Session>>;

pub fn new_store() -> SessionStore {
    Arc::new(DashMap::new())
}

/// Create a new session. Purges expired sessions first, then enforces the max-count
/// limit. Returns the new session ID, or an error if the store is at capacity.
pub fn create_session(store: &SessionStore) -> Result<String, &'static str> {
    let now = Instant::now();
    store.retain(|_, s| now.duration_since(s.created_at) < SESSION_TTL);

    if store.len() >= MAX_SESSIONS {
        return Err("too many active sessions");
    }

    let id = Uuid::new_v4().to_string();
    store.insert(
        id.clone(),
        Session {
            id: id.clone(),
            created_at: now,
        },
    );
    Ok(id)
}

pub fn get_session(store: &SessionStore, id: &str) -> Option<Session> {
    let entry = store.get(id)?;
    if Instant::now().duration_since(entry.created_at) >= SESSION_TTL {
        drop(entry);
        store.remove(id);
        return None;
    }
    Some(entry.clone())
}
