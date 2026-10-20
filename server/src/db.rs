use rusqlite::{Connection, OptionalExtension};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS accounts (
    id             TEXT PRIMARY KEY,
    email          TEXT NOT NULL UNIQUE COLLATE NOCASE,
    kdf_m_kib      INTEGER NOT NULL,
    kdf_t          INTEGER NOT NULL,
    kdf_p          INTEGER NOT NULL,
    kdf_salt       BLOB NOT NULL,
    auth_hash      TEXT NOT NULL,
    enc_pub        BLOB NOT NULL,
    sign_pub       BLOB NOT NULL,
    wrapped        BLOB NOT NULL,
    wrapped_rk     BLOB NOT NULL,
    recovery_hash  TEXT NOT NULL,
    created_at     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
    id             TEXT NOT NULL,
    account_id     TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name           TEXT NOT NULL,
    platform       TEXT NOT NULL,
    client_version TEXT,
    public_key     BLOB NOT NULL,
    created_at     TEXT NOT NULL,
    last_seen_at   TEXT,
    revoked        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (account_id, id)
);
CREATE TABLE IF NOT EXISTS tokens (
    hash           BLOB PRIMARY KEY,
    account_id     TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    device_id      TEXT NOT NULL,
    kind           TEXT NOT NULL,          -- access | refresh | revoked (a signed-out device's refresh token)
    scope          TEXT NOT NULL DEFAULT 'full',
    expires_at     INTEGER NOT NULL,
    used           INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS vaults (
    id                TEXT PRIMARY KEY,
    account_id        TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    key_id            BLOB NOT NULL,
    wrapped_vault_key BLOB NOT NULL,
    meta              BLOB,
    head_rev          INTEGER NOT NULL DEFAULT 0,
    created_at        TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS items (
    vault_id    TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    id          TEXT NOT NULL,
    rev         INTEGER NOT NULL,
    deleted     INTEGER NOT NULL,
    device_id   TEXT,
    envelope    BLOB,
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (vault_id, id)
);
CREATE INDEX IF NOT EXISTS items_by_rev ON items (vault_id, rev);
";

/// Ordered migrations on top of `SCHEMA`; `user_version` counts the ones applied.
const MIGRATIONS: &[&str] = &[
    // 1: organizations and shared vaults. An organization vault's `account_id` is the
    // organization's current owner (who can't delete their account while they own it).
    "
    CREATE TABLE orgs (
        id         TEXT PRIMARY KEY,
        name       TEXT NOT NULL,
        owner_id   TEXT NOT NULL,
        policies   TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL
    );
    CREATE TABLE owner_chain (
        org_id     TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        seq        INTEGER NOT NULL,
        account_id TEXT NOT NULL,
        enc_pub    BLOB NOT NULL,
        sign_pub   BLOB NOT NULL,
        signer_id  TEXT,
        sig        BLOB,
        PRIMARY KEY (org_id, seq)
    );
    CREATE TABLE members (
        org_id         TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        account_id     TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        role           TEXT NOT NULL,           -- owner | admin | member
        status         TEXT NOT NULL,           -- accepted | confirmed
        member_signer  TEXT,
        member_sig     BLOB,
        admin_signer   TEXT,
        admin_sig      BLOB,
        pending_vaults TEXT NOT NULL DEFAULT '[]', -- grants from the invite, applied at confirm
        joined_at      TEXT NOT NULL,
        PRIMARY KEY (org_id, account_id)
    );
    CREATE TABLE invites (
        id         TEXT PRIMARY KEY,
        org_id     TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        email      TEXT NOT NULL COLLATE NOCASE,
        role       TEXT NOT NULL,
        vaults     TEXT NOT NULL,
        token_hash BLOB NOT NULL UNIQUE,
        created_by TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        closed     INTEGER NOT NULL DEFAULT 0   -- accepted or cancelled
    );
    CREATE TABLE vault_members (
        vault_id   TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
        account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        permission TEXT NOT NULL,               -- read | write | manage
        PRIMARY KEY (vault_id, account_id)
    );
    CREATE TABLE vault_keys (
        vault_id   TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
        key_id     BLOB NOT NULL,
        account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        wrapped    BLOB NOT NULL,
        signer_id  TEXT,
        sig        BLOB,
        created_at TEXT NOT NULL,
        PRIMARY KEY (vault_id, key_id, account_id)
    );
    CREATE TABLE events (
        seq       INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id    TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        at        TEXT NOT NULL,
        kind      TEXT NOT NULL,
        actor_id  TEXT,
        target_id TEXT,
        vault_id  TEXT,
        detail    TEXT
    );
    ALTER TABLE vaults ADD COLUMN org_id TEXT REFERENCES orgs(id) ON DELETE CASCADE;
    ALTER TABLE vaults ADD COLUMN created_by TEXT;
    ALTER TABLE vaults ADD COLUMN rotation_due INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE items ADD COLUMN author_id TEXT;
    ALTER TABLE items ADD COLUMN key_id BLOB;
    UPDATE vaults SET created_by = account_id;
    INSERT INTO vault_keys (vault_id, key_id, account_id, wrapped, created_at)
        SELECT id, key_id, account_id, wrapped_vault_key, created_at FROM vaults;
    UPDATE items SET key_id = substr(envelope, 2, 16) WHERE envelope IS NOT NULL;
    CREATE INDEX vault_keys_by_account ON vault_keys (account_id);
    CREATE INDEX members_by_account ON members (account_id);
    CREATE INDEX invites_by_org ON invites (org_id, closed);
    CREATE INDEX events_by_org ON events (org_id, seq);
    ",
    // 2: blobs (encrypted session logs and attachments), named by their SHA-256.
    "
    CREATE TABLE blobs (
        vault_id   TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
        hash       TEXT NOT NULL,
        size       INTEGER NOT NULL,
        kind       TEXT NOT NULL,
        author_id  TEXT,
        created_at TEXT NOT NULL,
        data       BLOB NOT NULL,
        PRIMARY KEY (vault_id, hash)
    );
    ",
    // 3: single sign-on (OpenID Connect) per organization.
    "
    CREATE TABLE org_sso (
        org_id        TEXT PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
        issuer        TEXT NOT NULL,
        client_id     TEXT NOT NULL,
        client_secret TEXT NOT NULL,
        session_hours INTEGER NOT NULL DEFAULT 12,
        updated_at    TEXT NOT NULL
    );
    CREATE TABLE sso_logins (
        state_hash TEXT PRIMARY KEY,
        org_id     TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        account_id TEXT NOT NULL,
        device_id  TEXT NOT NULL,
        nonce      TEXT NOT NULL,
        verifier   TEXT NOT NULL,
        expires    INTEGER NOT NULL
    );
    CREATE TABLE sso_sessions (
        org_id     TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        account_id TEXT NOT NULL,
        device_id  TEXT NOT NULL,
        sub        TEXT NOT NULL,
        expires    INTEGER NOT NULL,
        PRIMARY KEY (org_id, account_id, device_id)
    );
    ",
    // 4: device approval (`require_device_approval`): requests and decisions per device.
    "
    CREATE TABLE device_approvals (
        org_id     TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        account_id TEXT NOT NULL,
        device_id  TEXT NOT NULL,
        status     TEXT NOT NULL,               -- pending | approved | denied
        requested  INTEGER NOT NULL,
        decided    INTEGER,
        decided_by TEXT,
        PRIMARY KEY (org_id, account_id, device_id)
    );
    ",
    // 5: SCIM provisioning: an organization's token (its SHA-256), and the users its identity
    // provider manages, by address (not the member list).
    "
    CREATE TABLE scim_tokens (
        org_id     TEXT PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
        token_hash BLOB NOT NULL UNIQUE,
        created_at TEXT NOT NULL,
        last_used  TEXT
    );
    CREATE TABLE scim_users (
        org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        id          TEXT NOT NULL,
        user_name   TEXT NOT NULL COLLATE NOCASE,
        external_id TEXT,
        active      INTEGER NOT NULL,
        created_at  TEXT NOT NULL,
        updated_at  TEXT NOT NULL,
        PRIMARY KEY (org_id, id),
        UNIQUE (org_id, user_name)
    );
    ",
    // 6: an organization's revision (`rev` in `GET /orgs`): bumped by every change its members'
    // apps fetch (details, members, device approvals, who can open its vaults).
    "
    ALTER TABLE orgs ADD COLUMN rev INTEGER NOT NULL DEFAULT 0;
    ",
    // 7: refresh tokens of deleted accounts (their tokens go with them), so their other devices
    // hear why for as long as the tokens would have lasted: `account_deleted`, or
    // `device_revoked` for a device signed out before the deletion (it still erases itself).
    "
    CREATE TABLE deleted_tokens (
        hash       TEXT PRIMARY KEY,
        code       TEXT NOT NULL,
        expires_at INTEGER NOT NULL
    );
    ",
];

/// Creates the schema and returns the per-server secret (used for fake prelogin salts).
pub(crate) fn init(conn: &mut Connection) -> rusqlite::Result<[u8; 32]> {
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.execute_batch(SCHEMA)?;
    let applied: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    for (i, sql) in MIGRATIONS
        .iter()
        .enumerate()
        .skip(usize::try_from(applied).unwrap_or(0))
    {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.pragma_update(None, "user_version", i64::try_from(i + 1).expect("few"))?;
        tx.commit()?;
    }
    let existing: Option<Vec<u8>> = conn
        .query_row("SELECT value FROM meta WHERE key = 'secret'", [], |r| {
            r.get(0)
        })
        .optional()?;
    if let Some(v) = existing.filter(|v| v.len() == 32) {
        return Ok(v.try_into().expect("checked length"));
    }
    let secret = crate::util::random::<32>();
    conn.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES ('secret', ?1)",
        [secret.as_slice()],
    )?;
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A database from before sharing keeps its vaults: each gets a one-generation key ring and
    /// items learn their key generation from the envelope header.
    #[test]
    fn upgrades_a_pre_sharing_database() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        conn.execute_batch(
            "INSERT INTO accounts (id, email, kdf_m_kib, kdf_t, kdf_p, kdf_salt, auth_hash, enc_pub, sign_pub,
                                   wrapped, wrapped_rk, recovery_hash, created_at)
             VALUES ('A', 'a@x', 65536, 2, 1, x'00', 'h', x'01', x'02', x'03', x'04', 'r', 't');
             INSERT INTO vaults (id, account_id, key_id, wrapped_vault_key, created_at)
             VALUES ('V', 'A', x'07070707070707070707070707070707', x'05', 't');
             INSERT INTO items (vault_id, id, rev, deleted, envelope, updated_at)
             VALUES ('V', 'I', 1, 0, x'0107070707070707070707070707070707FF', 't');",
        )
        .unwrap();
        init(&mut conn).unwrap();
        init(&mut conn).unwrap(); // idempotent
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, MIGRATIONS.len() as i64);
        let (account, wrapped): (String, Vec<u8>) = conn
            .query_row(
                "SELECT account_id, wrapped FROM vault_keys WHERE vault_id = 'V'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((account.as_str(), wrapped.as_slice()), ("A", &[5u8][..]));
        let key_id: Vec<u8> = conn
            .query_row("SELECT key_id FROM items WHERE id = 'I'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(key_id, [7u8; 16]);
        let created_by: String = conn
            .query_row("SELECT created_by FROM vaults WHERE id = 'V'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(created_by, "A");
    }
}
